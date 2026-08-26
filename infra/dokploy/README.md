# Dokploy Notes

Use the repository root `docker-compose.yml`. Set `JWT_SECRET` and `WEB_ORIGIN` in Dokploy's secret environment; do not commit `.env`. Publish `web` and the intended external API routes through TLS, keep `credential-detector` on `security-internal`, and block `/internal/v1/*` at the public ingress.

The Compose application is a development demo until the production gates in `docs/DEPLOYMENT.md` are completed.
