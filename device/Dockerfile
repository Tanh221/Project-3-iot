FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY pki_client.py entrypoint.py mqtt_client.py ./
ENTRYPOINT ["python", "entrypoint.py"]