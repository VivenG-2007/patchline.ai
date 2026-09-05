# ---- Base ----
FROM node:22-alpine AS base
WORKDIR /app
ENV NODE_ENV=production

# ---- Dependencies (cached layer) ----
FROM base AS deps
COPY package*.json ./
RUN npm ci --omit=dev

# ---- Runtime ----
FROM base AS runtime
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
COPY --from=deps /app/node_modules ./node_modules
COPY . .
USER appuser
# EXPOSE is documentation only — Render (and most Docker PaaS runtimes)
# inject a $PORT env var at runtime; env.js already reads it (falls back to
# 5000 locally), so the app binds correctly regardless of what Render
# assigns. The HEALTHCHECK below is written to follow the same $PORT value
# rather than hardcoding it, so it stays correct if that ever changes.
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const p=process.env.PORT||5000;require('http').get('http://127.0.0.1:'+p+'/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "src/server.js"]
