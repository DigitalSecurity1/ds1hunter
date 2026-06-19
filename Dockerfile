# DS1 Hunter - Dockerfile
# DigitalSecurity1 - "Hunt. Chain. Prove."

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc build-essential curl \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Static files
RUN cd web && python manage.py collectstatic --noinput || true

EXPOSE 18000

CMD ["sh", "-c", "cd web && python manage.py migrate && \
     gunicorn ds1hunter_project.asgi:application \
     --bind 0.0.0.0:18000 \
     --workers 2 \
     --worker-class uvicorn.workers.UvicornWorker \
     --timeout 120"]
