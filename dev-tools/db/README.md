# Dev Services (Postgres + Redis)

Start the local services:

```bash
cd /Users/Nuttayos.Suv/Desktop/ztd-poc/auth-service/dev-tools/db
docker compose up -d
```

Postgres connection string:

```
postgresql://postgres:postgres@localhost:5434/auth_service?schema=public
```

Redis connection string:

```
redis://localhost:6380/0
```

Stop the services:

```bash
docker compose down
```

Reset data (removes volume):

```bash
docker compose down -v
```
