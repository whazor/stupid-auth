load('ext://nix_flake', 'build_flake_image')


build_flake_image("stupid-auth", ".", "docker", deps=[
    "./src/",
    "./templates/",
    "./flake.nix"
])
allow_k8s_contexts('default')
allow_k8s_contexts('home-cluster')
default_registry('ttl.sh/nanne-stupid-auth')

domain=os.getenv('DOMAIN', 'example.com')

load('ext://helm_resource', 'helm_resource', 'helm_repo')
helm_repo('bjw-s', 'https://bjw-s.github.io/helm-charts/')
helm_resource('stupid-auth', 'bjw-s/app-template', flags=[
    "--values=./k8s/values.yaml",
    "--set=env.AUTH_DOMAIN={}".format(domain),
    "--set=ingress.main.hosts[0].host=stupid-auth.{}".format(domain),
    "--set=ingress.main.tls[0].hosts[0]=stupid-auth.{}".format(domain),
    "--version=1.5.1",
], image_deps=['stupid-auth'], image_keys=[('image.repository', 'image.tag')],
deps=[
    './k8s/values.yaml',
])

helm_resource('test-app', 'bjw-s/app-template', flags=[
    "--values=./k8s/test-app-values.yaml",
    "--version=1.5.1",
    "--set=ingress.main.annotations.nginx\\.ingress\\.kubernetes\\.io/auth-signin=https://stupid-auth.{}/login?rd=$scheme://$best_http_host$request_uri".format(domain),
    "--set=ingress.main.hosts[0].host=test-app.{}".format(domain),
    "--set=ingress.main.tls[0].hosts[0]=test-app.{}".format(domain),
], deps=[
    './k8s/test-app-values.yaml'
])