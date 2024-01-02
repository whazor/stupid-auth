def build_flake_image(ref, path = "", output = "", resultfile = "result", deps = []):
    build_cmd = "nix build {path}#{output} --refresh --out-link result-{ref}".format(
        path = path,
        output = output,
        ref = ref
    )
    commands = [
        "rm -rf ./result-stupid-auth-target",
        build_cmd,
        "./result-{ref} | docker load".format(ref = ref),
        'IMG_NAME="$(./result-{ref} | tar -Oxf - manifest.json | jq -r ".[0].RepoTags[0]")"'.format(ref = ref),
        "docker tag ${IMG_NAME} ${EXPECTED_REF}"
    ]
    custom_build(
        ref,
        command = [
            "nix-shell",
            "--packages",
            "coreutils",
            "gnutar",
            "jq",
            "--run",
            ";\n".join(commands),
        ],
        deps = deps,
        live_update=[
            sync('./result-stupid-auth-target', '/home/kah/result/'),
            run('date > /restart.txt')
        ]
    )

build_flake_image("stupid-auth", ".", "docker-live", deps=[
    "./flake.nix",
    "./result-stupid-auth-target",
])
allow_k8s_contexts('default')
allow_k8s_contexts('home-cluster')
default_registry('ttl.sh/nanne-stupid-auth')

domain=os.getenv('AUTH_DOMAIN')
if domain == None:
    fail("No domain set: AUTH_DOMAIN is None")

load('ext://helm_resource', 'helm_resource', 'helm_repo')
helm_repo('bjw-s', 'https://bjw-s.github.io/helm-charts/')
helm_resource('stupid-auth', 'bjw-s/app-template', flags=[
    "--values=./k8s/stupid-auth-values.yaml",
    "--set=env.AUTH_DOMAIN={}".format(domain),
    "--set=ingress.main.hosts[0].host=stupid-auth.{}".format(domain),
    "--set=ingress.main.tls[0].hosts[0]=stupid-auth.{}".format(domain),
    "--version=2.4.0",
], image_deps=['stupid-auth'], image_keys=[(
  'controllers.main.containers.main.image.repository', 
  'controllers.main.containers.main.image.tag')],
deps=[
    './k8s/stupid-auth-values.yaml',
])

helm_resource('test-app', 'bjw-s/app-template', flags=[
    "--values=./k8s/test-app-values.yaml",
    "--version=2.4.0",
    "--set=ingress.main.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-signin=https://stupid-auth.{}/login?rd=$scheme://$best_http_host$request_uri".format(domain),
    "--set=ingress.main.hosts[0].host=test-app.{}".format(domain),
    "--set=ingress.main.tls[0].hosts[0]=test-app.{}".format(domain),
], deps=[
    './k8s/test-app-values.yaml'
])
