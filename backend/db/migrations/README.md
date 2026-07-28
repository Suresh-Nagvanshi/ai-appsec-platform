# Database migrations

This project uses Alembic for schema migrations.

Typical workflow:

```bash
python -m alembic revision --autogenerate -m "describe change"
python -m alembic upgrade head
```
