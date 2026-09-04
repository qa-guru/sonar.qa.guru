# Deploy sonar.qa.guru

Bringup SonarQube Community Build + Postgres on Box 2.

## Prerequisites

- SSH alias `box2-ci`
- Host: `vm.max_map_count ≥ 524288`
- `~/.config/sonar/` — UI admin password locally; JDBC password in host `.env` (mode `600`)
- Docker + nginx + certbot

## Install order

```bash
./deploy/install-box2.sh
./deploy/configure-nginx-box2.sh
./deploy/smoke.sh
```

После первого UI-логина смените `admin` / `admin`. CI-токен — в `~/.config/sonar/ci-token`, не в этот репозиторий.
