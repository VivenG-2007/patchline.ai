FROM python:3.12-slim AS base
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENVIRONMENT=production

FROM base AS deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM base AS runtime
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser
COPY --from=deps /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin
COPY . .
USER appuser
# EXPOSE is documentation only — the actual bind port is dynamic (see CMD
# below). Render (and most PaaS Docker runtimes) inject a $PORT env var at
# runtime and route traffic to whatever port the container actually listens
# on; a container that ignores $PORT and only listens on a hardcoded port
# will fail health checks the moment the platform assigns a different one.
# 5002 is just the local-dev fallback (matches Settings.port in app/config.py).
EXPOSE 5002
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os,urllib.request,sys; p=os.environ.get('PORT','5002'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/health').status==200 else 1)"
# Shell form (not exec-form JSON array) so $PORT / $WEB_CONCURRENCY actually
# get expanded at container start — an exec-form CMD does NOT run through a
# shell and would bind literally to the string "${PORT}". 4 workers is a
# reasonable default for a small Render instance; tune via WEB_CONCURRENCY
# if you resize the plan.
CMD gunicorn app.main:app -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:${PORT:-5002} --workers ${WEB_CONCURRENCY:-4} --timeout 60
