# Llavero — Deployment notes

## PostgreSQL setup (scram-sha-256)

Run once on the database host as the `postgres` superuser:

```sql
-- Ensure scram-sha-256 is the default (Ubuntu 24.04 default is md5).
-- In postgresql.conf:
--   password_encryption = scram-sha-256
-- In pg_hba.conf replace md5 with scram-sha-256 for all local connections.

CREATE USER llavero WITH PASSWORD 'change-me' CONNECTION LIMIT 5;
CREATE DATABASE llavero OWNER llavero ENCODING 'UTF8' LC_COLLATE 'en_US.UTF-8' LC_CTYPE 'en_US.UTF-8' TEMPLATE template0;

-- App role (P1-T11 will add the restricted audit role separately)
GRANT CONNECT ON DATABASE llavero TO llavero;
```

## Internal CA TLS certificate

```bash
# Generate a key and CSR for llavero.internal
openssl genrsa -out llavero.internal.key 4096
openssl req -new -key llavero.internal.key -out llavero.internal.csr \
    -subj "/CN=llavero.internal/O=MrHome IT"

# Sign with your internal CA (adjust path to your CA key/cert)
openssl x509 -req -days 365 -in llavero.internal.csr \
    -CA /etc/ssl/internal-ca/ca.crt \
    -CAkey /etc/ssl/internal-ca/ca.key \
    -CAcreateserial \
    -out llavero.internal.crt

# Deploy
install -m 640 -o root -g llavero llavero.internal.key /etc/ssl/llavero/
install -m 644 llavero.internal.crt /etc/ssl/llavero/
```

## Systemd deployment

```bash
# Install service files
cp deploy/systemd/llavero.socket /etc/systemd/system/
cp deploy/systemd/llavero.service /etc/systemd/system/

# Create runtime dirs
install -d -m 750 -o llavero -g www-data /run/llavero /var/log/llavero

systemctl daemon-reload
systemctl enable --now llavero.socket
systemctl start llavero
```

## nginx

```bash
cp deploy/nginx/llavero.conf /etc/nginx/sites-available/llavero
ln -s /etc/nginx/sites-available/llavero /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```
