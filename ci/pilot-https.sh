#!/usr/bin/env bash
set -euo pipefail

tls_dir="$RUNNER_TEMP/appguardian-tls"
mkdir -p "$tls_dir"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj '/CN=AppGuardian CI loopback' -addext 'subjectAltName=IP:127.0.0.1' \
    -keyout "$tls_dir/server.key" -out "$tls_dir/server.crt"
cat > "$tls_dir/nginx.conf" <<'NGINX'
events {}
http {
    access_log off;
    server {
        listen 127.0.0.1:18443 ssl;
        ssl_certificate /pilot/server.crt;
        ssl_certificate_key /pilot/server.key;
        client_max_body_size 26m;

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_http_version 1.1;
            proxy_request_buffering off;
            proxy_read_timeout 80s;
        }
    }
}
NGINX

docker run -d --rm --name guardian-pilot-https --network host \
    -v "$tls_dir:/pilot:ro" -v "$tls_dir/nginx.conf:/etc/nginx/nginx.conf:ro" nginx:alpine
curl --fail --silent --show-error --retry 6 --retry-connrefused \
    --cacert "$tls_dir/server.crt" https://127.0.0.1:18443/readyz
