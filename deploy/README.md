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

## SAML (P2b)

Keycloak [auth.qa.guru](https://auth.qa.guru), client `sonar`. Локальный `admin` не трогать.

```bash
python3 ./deploy/saml.py inventory          # первый запуск → before.json
python3 ./deploy/saml.py ensure-groups
python3 ./deploy/saml.py seed-idp           # пилотные люди, пароли в ~/.config/auth-qa-guru/pilot.env
python3 ./deploy/saml.py configure
python3 ./deploy/saml.py login-check        # staff ≠ students; JIT-суффикс → handle
python3 ./deploy/saml.py verify
python3 ./deploy/saml.py break-glass        # sudo docker stop/start IdP-контейнера
```

Инвентарь и дамп БД — `~/.config/sonar/p2b-inventory/` (не git). Break-glass IdP: не `systemctl start` (oneshot RemainAfterExit) и не `compose up` от `qaguru` (env root 600).
