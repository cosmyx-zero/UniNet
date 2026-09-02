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

CMD sh -c 'uninet --host 0.0.0.0 --port ${PORT:-8000} --no-open'
