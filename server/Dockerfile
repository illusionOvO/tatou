# Server image: minimal Flask + Gunicorn
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates openssh-client \
 && rm -rf /var/lib/apt/lists/*

# Copy project description, to instal dependencies
COPY pyproject.toml /app/pyproject.toml



# Copy sources after dependencies installation
COPY . /app/server
COPY flag /app/flag
COPY entrypoint.sh /app/entrypoint.sh
RUN pip install --no-cache-dir -e .

EXPOSE 5000

# Default command runs the web server
<<<<<<< HEAD
CMD ["gunicorn", "-b", "0.0.0.0:5000", "server.src.server:app"]
=======
CMD ["./entrypoint.sh"]
>>>>>>> 568f7f4651c1599a530b94d7100991faf63d11bb

