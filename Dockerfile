# One container that serves the React app and the API from the same origin.
# Used for single-service hosting (render.yaml). Local development uses
# docker-compose.yml instead: separate API and nginx containers plus PostgreSQL.

# --- 1. build the React app ---------------------------------------------------
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
# Same origin as the API, so the bundle calls relative /api URLs.
ENV VITE_API_URL=""
RUN npm run build

# --- 2. the API, which also serves the built app ----------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    LOOKOUT_STATIC_DIR=/app/static

WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt

COPY backend/lookout ./lookout
COPY backend/datasets ./datasets
COPY backend/trained_models/metrics.json ./trained_models/metrics.json
# Train once, at build time, from the committed dataset.
RUN python -c "from lookout.ml.model import ThreatClassifier; ThreatClassifier.load_or_train()"

COPY --from=web /web/dist ./static

RUN useradd --create-home --uid 10001 lookout && chown -R lookout /app
USER lookout

# Hosts such as Render set PORT; locally it defaults to 8077.
ENV PORT=8077
EXPOSE 8077
CMD ["sh", "-c", "exec uvicorn lookout.api:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips '*'"]
