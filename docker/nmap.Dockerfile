FROM python:3.11-slim

RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*
RUN pip install flask python-nmap

COPY docker/nmap_service.py /app/nmap_service.py

WORKDIR /app
EXPOSE 8081
CMD ["python", "nmap_service.py"]
