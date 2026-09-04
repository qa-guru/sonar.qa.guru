#!/usr/bin/env bash
# rsync compose to Box2 /opt/sonar.qa.guru and docker compose up.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOST="${SONAR_DEPLOY_HOST:-box2-ci}"
REMOTE="/opt/sonar.qa.guru"
ENV_FILE="${SONAR_COMPOSE_ENV:-${HOME}/.config/sonar/compose.env}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "FAIL: ${ENV_FILE} missing (POSTGRES_PASSWORD). Copy from .env.example." >&2
  exit 1
fi

ssh "${HOST}" "sudo mkdir -p '${REMOTE}' && sudo chown qaguru:qaguru '${REMOTE}'"

rsync -az --delete \
  --exclude '.git/' \
  --exclude '.env' \
  --exclude 'deploy/' \
  --exclude 'README.md' \
  "${ROOT}/" "${HOST}:${REMOTE}/"

scp -q "${ENV_FILE}" "${HOST}:${REMOTE}/.env"
ssh "${HOST}" "chmod 600 '${REMOTE}/.env'"
ssh "${HOST}" "sudo sysctl -w vm.max_map_count=524288 >/dev/null"
ssh "${HOST}" "cd '${REMOTE}' && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
ssh "${HOST}" "cd '${REMOTE}' && docker compose -f docker-compose.yml -f docker-compose.prod.yml ps"

echo "OK: Sonar compose on ${HOST}:${REMOTE}"
