#!/usr/bin/env bash
# nginx TLS vhost for sonar.qa.guru on Box 2 (proxy → 127.0.0.1:9000).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NGINX_SRC="$(cd "${SCRIPT_DIR}/.." && pwd)/nginx/sonar.qa.guru.nginx"
HOST="${SONAR_DEPLOY_HOST:-box2-ci}"

if [[ ! -f "${NGINX_SRC}" ]]; then
  echo "FAIL: ${NGINX_SRC} missing" >&2
  exit 1
fi

ssh "${HOST}" 'bash -s' <<'REMOTE'
set -euo pipefail
sudo tee /etc/nginx/sites-available/sonar >/dev/null <<'HTTPONLY'
server {
    listen 80;
    listen [::]:80;
    server_name sonar.qa.guru;

    location ^~ /.well-known/acme-challenge/ {
        default_type text/plain;
        root /var/www/html;
        try_files $uri =404;
    }

    location / {
        include /etc/nginx/proxy_params;
        proxy_pass http://127.0.0.1:9000;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
HTTPONLY
sudo ln -sf /etc/nginx/sites-available/sonar /etc/nginx/sites-enabled/sonar
sudo nginx -t && sudo systemctl reload nginx
REMOTE

if ssh "${HOST}" 'test -f /etc/letsencrypt/live/sonar.qa.guru/fullchain.pem'; then
  echo "LE cert already present"
else
  ssh "${HOST}" 'sudo certbot certonly --webroot -w /var/www/html -d sonar.qa.guru --non-interactive --agree-tos -m admin@qa.guru'
fi

scp -q "${NGINX_SRC}" "${HOST}:/tmp/sonar.qa.guru.nginx"
ssh "${HOST}" 'sudo mv /tmp/sonar.qa.guru.nginx /etc/nginx/sites-available/sonar && sudo ln -sf /etc/nginx/sites-available/sonar /etc/nginx/sites-enabled/sonar && sudo nginx -t && sudo systemctl reload nginx'

echo "Box2 nginx sonar.qa.guru + LE configured."
