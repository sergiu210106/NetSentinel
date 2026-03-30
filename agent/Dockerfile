FROM python:3.10-slim

# Install system dependencies required for packet sniffing
RUN apt-get update && apt-get install -y libpcap-dev tcpdump && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Environment variables for the socket connection
ENV SERVER_IP=127.0.0.1
ENV SERVER_PORT=9999

CMD ["python", "agent.py"]