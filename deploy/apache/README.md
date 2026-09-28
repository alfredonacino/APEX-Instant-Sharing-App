# Serving the app at instantsharing.supportlab.cloud

Apache on the app server terminates the public certificate and reverse-proxies
to the application's own HTTPS listener on 3443. Both legs are encrypted: the
public one with a real certificate, the backend one with the app's self-signed
pair, which is only ever presented to Apache on loopback.

    browser ──https(443)──▶ Apache ──https(3443)──▶ node (pm2: apex-instant-sharing-app)

Everything below needs root, which this deployment account does not have
without a password, so these are the steps to run by hand.

## 1. Point the name at this server

Check where the name points before anything else:

    dig +short instantsharing.supportlab.cloud

If it resolves to something other than this server - a `*.supportlab.cloud`
wildcard pointing at unrelated hosting, for example - nothing below is reachable
by that name yet.

Either add an internal DNS record pointing the name at this server's LAN address
for internal use, or publish an A record pointing at a public address that
forwards 80 and 443 here. Let's Encrypt's http-01 challenge only works in the
second case.

## 2. Install the vhosts

    sudo install -m 644 instantsharing.supportlab.cloud.conf \
        /etc/apache2/sites-available/
    sudo install -m 644 instantsharing.supportlab.cloud-le-ssl.conf \
        /etc/apache2/sites-available/

    sudo mkdir -p /var/www/instantsharing.supportlab.cloud/{html,log}

## 3. A certificate

Real one, once the name resolves here from the internet:

    sudo certbot certonly --webroot -w /var/www/letsencrypt \
        -d instantsharing.supportlab.cloud
    # then point SSLCertificateFile/SSLCertificateKeyFile at
    # /etc/letsencrypt/live/instantsharing.supportlab.cloud/

Self-signed, to bring it up on the LAN immediately (browsers will warn):

    sudo mkdir -p /etc/ssl/apex-apache-manager/instantsharing.supportlab.cloud
    sudo openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout /etc/ssl/apex-apache-manager/instantsharing.supportlab.cloud/privkey.pem \
        -out   /etc/ssl/apex-apache-manager/instantsharing.supportlab.cloud/fullchain.pem \
        -subj "/CN=instantsharing.supportlab.cloud" \
        -addext "subjectAltName=DNS:instantsharing.supportlab.cloud"
    sudo chmod 600 /etc/ssl/apex-apache-manager/instantsharing.supportlab.cloud/privkey.pem

## 4. Enable and reload

    sudo a2ensite instantsharing.supportlab.cloud instantsharing.supportlab.cloud-le-ssl
    sudo apache2ctl configtest
    sudo systemctl reload apache2

## 5. Check

    curl -I https://instantsharing.supportlab.cloud/healthz
    curl -I http://instantsharing.supportlab.cloud/        # expect 301 to https

The modules this needs (`proxy`, `proxy_http`, `ssl`, `headers`, `rewrite`) are
already enabled on this server.

## Why the app still terminates its own TLS

The backend keeps `SSL_ENABLED=true` on 3443 rather than serving plain HTTP, so
traffic between Apache and the app is encrypted too, and the app can still be
reached directly over TLS on the LAN if Apache is ever out of the picture. The
app is told it is behind one proxy (`TRUST_PROXY=1`), which is what puts the
real visitor's IP in the audit trail instead of Apache's own address.
