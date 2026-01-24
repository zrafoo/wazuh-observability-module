FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir \
    fastapi \
    numpy \
    opensearch-py \
    pandas \
    psycopg2-binary \
    uvicorn

EXPOSE 3000

CMD ["python", "src/main.py"]
