# stupid-auth

## What is this?

This is a simple authentication server that uses secure cookies to authenticate users. It is meant for home lab use and is not meant to be used in production.

Currently, it only supports forward auth from NGINX, and can be used to add authentication to services that do not support auth, or support auth via header.

## Is this secure?

Every authentication system makes different tradeoffs. This system is designed to be easy to use and secure enough for home lab use.

The goal is to take the tradeoffs that only make sense for a home lab environment. Using this in an enterprise setting would be stupid. Can you imagine a sys admin restarting the auth server because one user forgot their password?

### Are we secure yet?

To check:

- [ ] [A01:2021-Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [ ] [A02:2021-Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [ ] [A03:2021-Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [ ] [A04:2021-Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [ ] [A05:2021-Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)
- [ ] [A06:2021-Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)
- [ ] [A07:2021-Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [ ] [A08:2021-Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- [ ] [A09:2021-Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)
- [ ] [A10:2021-Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

## Why?

Alternative auth systems often use Redis and/or PostgreSQL to manage their state and users. But maintaining two databases can be a lot of effort, and if one of them breaks your entire cluster can become locked.

So we want to have a rock-solid auth server that is stupidly simple. Instead of storing users in a database, we store them in a YAML file. Instead of storing sessions in Redis, we store them in memory. 

## Goals

- [ ] [Cluster mode](https://github.com/whazor/stupid-auth/issues/4)
- [ ] [Oauth2](https://github.com/whazor/stupid-auth/issues/5)
- [ ] [passkeys](https://github.com/whazor/stupid-auth/issues/6)


## Supported

- [x] nginx ingress
- [ ] traefik
- [ ] haproxy
- [ ] envoy


## Usage

Setup stupid-auth, you might want to first create an empty users k8s secret to start the application.

Open `https://stupid-auth.example.com/tutorial` in your browser and follow the instructions.

From the tutorial you will learn how to create a users.yaml file and how to create a secret from it.

```bash
kubectl create secret generic stupid-auth-users --from-file=users.yaml
```
