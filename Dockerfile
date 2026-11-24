FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY alembic.ini import_logs.py ./
COPY migrations ./migrations
COPY loganalyzer ./loganalyzer

EXPOSE 8000

CMD ["sh", "-c", "python -m alembic upgrade head && python -m uvicorn loganalyzer.api.app:app --host 0.0.0.0 --port 8000"]