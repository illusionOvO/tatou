# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential make pkg-config \
    zlib1g-dev libjpeg-dev libopenjp2-7-dev \
    tesseract-ocr libleptonica-dev \
 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

COPY  . .

# Copy sources after dependencies installation
RUN [ -f "/app/entrypoint.sh" ] && chmod +x /app/entrypoint.sh || true

EXPOSE 5000

# Default command runs the web server
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server.src.server:app"]
# CMD ["./entrypoint.sh"]