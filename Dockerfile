FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/data
WORKDIR /opt/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY scripts ./scripts
VOLUME ["/data"]
EXPOSE 8080/tcp 1812/udp 1813/udp 2055/udp
CMD ["python", "-m", "app.main"]
