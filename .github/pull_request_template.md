## Qué cambia
-

## Cómo probarlo
- `make all` y `make idempotence`

## Checklist
- [ ] Tests nuevos o actualizados y en verde (`make test`, `make lint`)
- [ ] `uv run hlab validate` sin errores; `docs/excepciones.md` y `schemas/v1` regenerados si cambió el modelo
- [ ] Sin secretos ni datos personales en el diff
