FROM node:22-bookworm-slim AS build
WORKDIR /workspace
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/package.json
COPY apps/web/package.json apps/web/package.json
RUN npm ci --workspace @attestguard/api --include-workspace-root
COPY apps/api apps/api
COPY policies policies
RUN npm run build --workspace @attestguard/api

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=development PORT=8080 POLICY_FILE=/app/policies/default.yaml
RUN rm -rf /usr/local/lib/node_modules/npm \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx \
    && useradd --system --uid 10001 --no-create-home attestguard
WORKDIR /app
COPY --from=build --chown=10001:10001 /workspace/node_modules ./node_modules
COPY --from=build --chown=10001:10001 /workspace/apps/api/dist ./dist
COPY --from=build --chown=10001:10001 /workspace/policies ./policies
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/ready').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "dist/main.js"]
