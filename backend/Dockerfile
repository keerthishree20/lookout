FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY lookout ./lookout
COPY datasets ./datasets
COPY trained_models/metrics.json ./trained_models/metrics.json

# Train the classifier once, at build time, from the committed dataset, so the
# container starts with a model instead of training on first request.
RUN python -c "from lookout.ml.model import ThreatClassifier; ThreatClassifier.load_or_train()"

RUN useradd --create-home --uid 10001 lookout && chown -R lookout /app
USER lookout

EXPOSE 8077
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8077/api/health', timeout=4)"

CMD ["uvicorn", "lookout.api:app", "--host", "0.0.0.0", "--port", "8077", "--proxy-headers"]
