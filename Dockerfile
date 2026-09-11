FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE requirements.txt ./

COPY src ./src
COPY config ./config

RUN pip install --upgrade pip setuptools wheel && \
    pip install .

COPY . .

# Single gevent worker: app.config state is process-local and SSE subscribers
# are greenlets in the same gevent hub, so one worker is both correct and safe.
CMD sh -c 'gunicorn "uninet.wsgi:app" \
    --worker-class gevent \
    --workers 1 \
    --bind 0.0.0.0:${PORT:-8000} \
    --timeout 120 \
    --keep-alive 75 \
    --log-level info'
