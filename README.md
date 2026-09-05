# sonar.qa.guru

Production **SonarQube Community Build** on Box 2 — **https://sonar.qa.guru**

Сканы и quality gate для эталона и учебных репозиториев. JDBC-пароль и токены в git **не** кладём.

| | |
|--|--|
| URL | https://sonar.qa.guru |
| Edition | Community Build **26.7.0.124771** (`sonarqube:26.7.0.124771-community`) |
| Host | Box 2 `89.248.193.83` — рядом Jenkins, Grafana, Ollama; **не** Box 3 |
| Path | `/opt/sonar.qa.guru` |
| Stack | Docker Compose: SonarQube + Postgres 16 (Postgres без publish) |
| Auth | SAML → [auth.qa.guru](https://auth.qa.guru) (P2b). Локальный `admin` — break-glass |
| CI | `SONAR_TOKEN` — env / GH secret, никогда в argv |

## Для учащихся

Смотрите compose: внутренний Postgres, pin образа, loopback `:9000`, nginx снаружи.

```bash
git clone https://github.com/qa-guru/sonar.qa.guru.git
cd sonar.qa.guru
cp .env.example .env          # POSTGRES_PASSWORD, не коммитить
# один раз на Linux-хосте:
# sudo sysctl -w vm.max_map_count=524288
docker compose up -d
curl -sf http://127.0.0.1:9000/api/system/status
```

UI: http://127.0.0.1:9000 — первый логин `admin` / `admin`, сразу сменить.

На Docker Desktop, если Elasticsearch не стартует: в `.env` раскомментируйте `SONAR_ES_BOOTSTRAP_CHECKS_DISABLE=true` (только локально).

## Структура

| Путь | Назначение |
|------|------------|
| [`docker-compose.yml`](docker-compose.yml) | Sonar + Postgres, сеть `sonar_internal` |
| [`docker-compose.prod.yml`](docker-compose.prod.yml) | `restart: unless-stopped` |
| [`.env.example`](.env.example) | JDBC / порт placeholders |
| [`nginx/sonar.qa.guru.nginx`](nginx/sonar.qa.guru.nginx) | TLS vhost → `127.0.0.1:9000` |
| [`deploy/`](deploy/) | Box2 install / nginx / smoke |

Секреты (не в git): `~/.config/sonar/ci-token`, `admin-token`, `admin.password`.

Quality gate profiles и projectKey — канон курса, не этот репозиторий. Инстанс: [sonar.qa.guru](https://sonar.qa.guru).

Monorepo wrapper: `projects/services-home/sonar-qa-guru-home/`.
