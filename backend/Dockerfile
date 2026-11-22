FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY guardian guardian
RUN mkdir /worker-ipc /catalog \
    && chown 10002:10001 /worker-ipc && chmod 0750 /worker-ipc \
    && chown 10001:10001 /catalog
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "guardian.api:app", "--host", "0.0.0.0", "--no-access-log"]
