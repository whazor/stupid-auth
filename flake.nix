{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-23.05";
    nixpkgs-unstable.url = "github:NixOS/nixpkgs/nixos-unstable";
    devenv.url = "github:cachix/devenv";

    crane.url = "github:ipetkov/crane";
    crane.inputs.nixpkgs.follows = "nixpkgs";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nix2container.url = "github:nlewo/nix2container";
    nix2container.inputs.nixpkgs.follows = "nixpkgs";
    mk-shell-bin.url = "github:rrbutani/nix-mk-shell-bin";
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.devenv.flakeModule ];
      systems = [ "x86_64-linux" ];

      perSystem = { config, self', inputs', pkgs, system, ... }:
        let
          opensslStatic = pkgs.pkgsStatic.openssl;
          buildArgs = rec {
            # nativeBuildInputs = with pkgs; [
            #   llvmPackages.llvm
            #   llvmPackages.bintools
            #   llvmPackages.libcxxClang
            # ];
            nativeBuildInputs = [ pkgs.mold pkgs.pkg-config ];
            buildInputs = [
              # Add additional build inputs here
              pkgs.openssl
              pkgs.openssl.dev
            ];
            OPENSSL_NO_VENDOR = "1";
            OPENSSL_LIB_DIR = "${opensslStatic.out}/lib";
            OPENSSL_INCLUDE_DIR = "${opensslStatic.dev}/include";
          };
          # craneLib = inputs.crane.lib.${system}.overrideToolchain
          #   inputs.fenix.packages.${system}.minimal.toolchain;
          # craneMaxLib = inputs.crane.lib.${system}.overrideToolchain
          #   inputs.fenix.packages.${system}.complete.toolchain;
          craneLib = inputs.crane.lib.${system};
          craneMaxLib = inputs.crane.lib.${system};
          manifest = (pkgs.lib.importTOML ./Cargo.toml).package;

          templatesFilter = path: _type:
            builtins.match ".*templates.*" path != null;
          userYamlFilter = path: _type:
            builtins.match ".*users.yaml" path != null;
          fullFilter = path: type:
            (templatesFilter path type)
            || (craneLib.filterCargoSources path type)
            || (userYamlFilter path type);
          src = pkgs.lib.cleanSourceWith {
            src = craneLib.path ./.;
            filter = fullFilter;
          };
          commonArgs = buildArgs // {
            inherit src;
            # Additional environment variables can be set directly
            # MY_CUSTOM_VAR = "some value";
            TAILWIND_CSS = "${self'.packages.stupid-auth-css}/static/tw.css";
          };
          cargoArtifacts =
            craneLib.buildDepsOnly (buildArgs // { inherit src; });
          stupid-auth-crate = craneLib.buildPackage (commonArgs // {
            # src = craneLib.cleanCargoSource (craneLib.path ./.);

            inherit cargoArtifacts;
          });
          advisory-db = inputs.advisory-db;
          docker = {
            name = "stupid-auth";
            tag = "latest";
            config = {
              # Entrypoint = [ "stupid-auth" ];
              Cmd = [ "stupid-auth" ];
              Labels = {
                "org.opencontainers.image.source" =
                  "https://github.com/whazor/stupid-auth";
                "org.opencontainers.image.description" =
                  "A stupid authentication server";
                "org.opencontainers.image.licenses" = "MIT";
              };
            };

            contents = [
              pkgs.openssl
              pkgs.openssl.dev
              pkgs.pkgsStatic.openssl
              pkgs.pkg-config
              stupid-auth-crate
              (pkgs.fakeNss.override {
                extraPasswdLines = [ "kah:x:568:568::/home/kah:/bin/false" ];
                extraGroupLines = [ "kah:x:568:" ];
              })
              (pkgs.runCommand "empty-templates" { } ''
                mkdir -p $out/tmp/templates
              '')
            ];
          };
        in {
          checks = {
            inherit stupid-auth-crate;
            stupid-auth-crate-clippy = craneMaxLib.cargoClippy (commonArgs // {
              inherit cargoArtifacts;
              cargoClippyExtraArgs = "--all-targets -- --deny warnings";
            });
            stupid-auth-crate-audit = craneMaxLib.cargoAudit
              (commonArgs // { inherit src advisory-db; });
            stupid-auth-crate-nextest = craneMaxLib.cargoNextest ({
              src = pkgs.lib.cleanSourceWith {
                src = craneMaxLib.path ./.;
                filter = path: type:
                  (fullFilter path type) || (userYamlFilter path type);
              };
            } // commonArgs // {
              inherit cargoArtifacts;

              partitions = 1;
              partitionType = "count";
            });
          };

          packages.stupid-auth-css = let
            tailwindConfigFilter = path: type:
              builtins.match ".*tailwind.config.js" path != null;
            templatesFilter = path: type:
              builtins.match ".*templates.*" path != null;
          in pkgs.stdenv.mkDerivation {
            src = pkgs.lib.cleanSourceWith {
              src = ./.;
              filter = path: type:
                (tailwindConfigFilter path type) || (templatesFilter path type);
            };
            name = "stupid-auth-css";
            buildInputs = [ pkgs.nodePackages_latest.tailwindcss ];
            phases = [ "buildPhase" ];
            buildPhase = ''
              mkdir -p $out/static/
              cd $src
              ${pkgs.nodePackages_latest.tailwindcss}/bin/tailwind build -o $out/static/tw.css
              sha1sum $out/static/tw.css | head -c 40 > $out/static/tw.css.sha1
            '';
          };
          packages.stupid-auth = stupid-auth-crate;

          packages.docker = pkgs.dockerTools.streamLayeredImage docker;
          # we use entr for live reloading
          packages.docker-live = pkgs.dockerTools.streamLayeredImage (docker
            // {
              contents = docker.contents ++ [
                pkgs.gnutar
                pkgs.busybox
                pkgs.entr
                opensslStatic
                (pkgs.runCommand "stupid-auth-dev" { } ''
                  mkdir -p $out/home/kah/
                  touch $out/restart.txt
                  cp -Lr ${stupid-auth-crate}/ $out/home/kah/result/
                '')

              ];

              config = {
                # Cmd = [ "${pkgs.entr}/bin/entr" "-r" "/bin/stupid-auth" ];
                Env = [
                  "OPENSSL_NO_VENDOR=1"
                  "OPENSSL_LIB_DIR=${opensslStatic.dev}/lib"
                  "OPENSSL_INCLUDE_DIR=${opensslStatic.dev}/include"
                ];
                Cmd = [
                  "busybox"
                  "sh"
                  "-c"
                  "echo '/restart.txt' | entr -nrz /home/kah/result/bin/stupid-auth"
                ];
                # Cmd = [ "start" "/home/kah/stupid-auth" ];
              };
            });
          # we upload to ghcr.io from github actions
          packages.publish-docker = pkgs.writeScriptBin "publish-docker" ''
            #!${pkgs.runtimeShell}
            echo "$GITHUB_TOKEN" | skopeo login ghcr.io -u whazor --password-stdin
            ${self'.packages.docker} | gzip --fast | skopeo copy docker-archive:/dev/stdin docker://ghcr.io/whazor/stupid-auth:${manifest.version}
          '';

          devenv.shells.default = { config, ... }:
            let unstable = inputs'.nixpkgs-unstable.legacyPackages;
            in {
              # https://devenv.sh/reference/options/
              env.STATIC_DIR = "${config.env.DEVENV_ROOT}/static/";
              env.TAILWIND_CSS =
                "${self'.packages.stupid-auth-css}/static/tw.css";

              # pre-commit = {
              # hooks.commitlint = {
              #   enable = true;
              #   description = "Commitlint hook";
              #   entry =  "${pkgs.commitlint}/bin/commitlint --edit";
              #   # language = "node";
              #   pass_filenames = false;
              # };
              # };

              packages = [
                # config.packages.default 
                # self'.packages.stupid-auth
                pkgs.traefik
                # pkgs.tilt
                unstable.tilt
                # inputs.nixpkgs-unstable.packages.${pkgs.stdenv.hostPlatform.system}.tilt

                pkgs.python3 # used by tilt
                pkgs.cargo-watch
                pkgs.nodePackages_latest.tailwindcss
                pkgs.dive
                pkgs.lld
                pkgs.openssl
                pkgs.mold
                pkgs.entr
                pkgs.llvmPackages_16.clang-unwrapped
              ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin
                (with pkgs.darwin.apple_sdk; [
                  frameworks.Security
                  frameworks.CoreFoundation
                  frameworks.CoreServices
                ]);

              scripts.web.exec = ''
                ${pkgs.traefik}/bin/traefik --entrypoints.web.address=:8500 --providers.file.filename=router.yaml
              '';
              scripts.run.exec = ''
                ${pkgs.cargo-watch}/bin/cargo-watch -x run
              '';
              scripts.build.exec = ''
                ${pkgs.cargo-watch}/bin/cargo-watch -x 'build --release'
              '';
              scripts.css.exec = ''
                ${pkgs.nodePackages_latest.tailwindcss}/bin/tailwind -w -o $DEVENV_ROOT/static/tw.css
              '';
              scripts.check.exec = ''
                nix flake check --impure
              '';

              scripts.docker-run.exec = ''
                docker run --rm -it -p 8000:8000 stupid-auth:latest
              '';
              scripts.docker-load.exec = ''
                nix build .#docker-live && ./result | docker load && rm ./result
              '';

              enterShell = ''
                mkdir -p $DEVENV_ROOT/static/
              '';

              # https://devenv.sh/languages/
              # languages.nix.enable = true;
              languages.rust.enable = true;
            };
        };
    };
}
