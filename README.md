# Certcentral

Certcentral is a Python 3 application that is to be used to centrally request configured TLS
certificates from ACME servers, then make them available to authorised API users. The API is
intended to sit behind uwsgi and nginx running TLS client certificate checking based on a private
CA. It can support http-01 and dns-01 challenges.

Certcentral itself consists of two parts:
* The backend in certcentral.py, which is responsible for generating initial certificates and then
  replacing them with live ones from the specified ACME server.
* The API in api.py/uwsgi.py, which is responsible for taking requests from users,
  and distributing the certificates saved by the backend.

It is intended for use in multi-server environments where any one of several actual servers with no
shared filesystem are required to terminate TLS connections, where it is not feasible to have each
server requesting their own certificates from ACME servers.

One variant of the API permits simple use by puppet.
It is hoped that eventually this will be used to handle certificates for wikipedia.org and co.

The license in use is GPL v3+ and the main developers are Alex Monk <krenair@gmail.com> and Valentin
Gutierrez <vgutierrez@wikimedia.org>.

## Configuration file example
Certcentral expects its configuration file in /etc/certcentral/config.yaml by default
```yaml
accounts:
-
    id: account_id_here
    directory: "https://acme-v02.api.letsencrypt.org/directory"
certificates:
    testing:
        CN: certcentraltest.beta.wmflabs.org
        SNI:
        - certcentraltest.beta.wmflabs.org
        challenge: http-01
challenges:
    dns-01:
        validation_dns_servers:
        - 127.0.0.1
        sync_dns_servers:
        - 127.0.0.1
```

It also supports per-certificate configuration in /etc/certcentral/conf.d. conf.d file example:
```yaml
certname: default_account_certificate
hostname: deployment-certcentral-testclient02.deployment-prep.eqiad.wmflabs
```
