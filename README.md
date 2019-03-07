# acme-chief

acme-chief is a Python 3 application that is to be used to centrally request configured TLS
certificates from ACME servers, then make them available to authorised API users. The API is
intended to sit behind uwsgi and nginx running TLS client certificate checking based on a private
CA. It can support http-01 and dns-01 challenges.

acme-chief itself consists of two parts:
* The backend in acme_chief.py, which is responsible for generating initial certificates and then
  replacing them with live ones from the specified ACME server.
* The API in api.py/uwsgi.py, which is responsible for taking requests from users,
  and distributing the certificates saved by the backend.

It is intended for use in multi-server environments where any one of several actual servers with no
shared filesystem are required to terminate TLS connections, where it is not feasible to have each
server requesting their own certificates from ACME servers.

One thing to note is that there are two stages when acme-chief is outputting certificates: the
initial, self-signed certificate, and the trusted one issued through ACME. The initial stage is
done to help with cases where servers need a dummy certificate to start up, which may be required
in order to *get* the publicly-trusted certificates at all (thus resolving a chicken-and-egg
problem). A side-effect of this is zero-byte PEM files for the chain, which for self-signed
certificates is empty.

One variant of the API permits simple use by puppet.
It is hoped that eventually this will be used to handle certificates for wikipedia.org and co.

The license in use is GPL v3+ and the main developers are Alex Monk <krenair@gmail.com> and Valentin
Gutierrez <vgutierrez@wikimedia.org>.

## Configuration file example
acme-chief expects its configuration file in /etc/acme-chief/config.yaml by default
```yaml
accounts:
-
    id: account_id_here
    directory: "https://acme-v02.api.letsencrypt.org/directory"
certificates:
    testing:
        CN: acmechieftest.beta.wmflabs.org
        SNI:
        - acmechieftest.beta.wmflabs.org
        staging_time: 3600
        challenge: http-01
        authorized_hosts:
        - cp1008.eqiad.wmnet
        authorized_regexes:
        - '^cp100[1-9]\.eqiad\.wmnet$'
challenges:
    dns-01:
        validation_dns_servers:
        - 127.0.0.1
        sync_dns_servers:
        - 127.0.0.1
        zone_update_cmd: /bin/echo
        zone_update_cmd_timeout: 60.0
api:
    clients_root_directory: /etc/acmecerts
```

It also supports per-certificate configuration in /etc/acme-chief/conf.d. conf.d file example:
```yaml
certname: default_account_certificate
hostname: deployment-acmechief-testclient02.deployment-prep.eqiad.wmflabs
```
