FROM python:3.11-slim

WORKDIR /app

# Install dependencies for Apache Tika and MongoDB
RUN apt-get update && apt-get install -y \
    default-jre \
    wget \
    unzip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Download and install Apache Tika server
RUN wget https://dlcdn.apache.org/tika/2.9.1/tika-server-standard-2.9.1.jar -O /opt/tika-server.jar

# Download and install YARA-X (assuming it's available as a binary)
RUN mkdir -p /opt/yara-x \
    && wget https://github.com/VirusTotal/yara-x/releases/download/v0.1.0/yara-x-v0.1.0-x86_64-linux.tar.gz -O /tmp/yara-x.tar.gz \
    && tar -xzf /tmp/yara-x.tar.gz -C /opt/yara-x \
    && ln -s /opt/yara-x/yax /usr/local/bin/yax \
    && rm /tmp/yara-x.tar.gz

# Copy requirements first for better caching
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY backend/ .

# Create necessary directories
RUN mkdir -p /app/data/yara_rules \
    && mkdir -p /app/data/keywords \
    && mkdir -p /app/data/samples \
    && mkdir -p /app/data/uploads

# Set environment variables
ENV MONGODB_URI=mongodb://mongodb:27017/
ENV MONGODB_DB=cipher_db
ENV TIKA_SERVER_URL=http://localhost:9998
ENV PYTHONPATH=/app

# Port for FastAPI
EXPOSE 8000

# Port for Tika Server
EXPOSE 9998

# Start script
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]