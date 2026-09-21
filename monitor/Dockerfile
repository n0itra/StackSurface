FROM python:3.12.7-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN useradd --create-home --shell /usr/sbin/nologin monitor \
    && mkdir -p /data \
    && chown -R monitor:monitor /app /data
USER monitor

CMD ["python", "-m", "app.monitor"]
