# Dev DB (Postgres)

Start the database:

```bash
cd /Users/Nuttayos.Suv/Desktop/ztd-poc/auth-service/dev-tools/db
docker compose up -d
```

Connection string:

```
postgresql://postgres:postgres@localhost:5433/auth_service?schema=public
```

Stop the database:

```bash
docker compose down
```

Reset data (removes volume):

```bash
docker compose down -v
```
