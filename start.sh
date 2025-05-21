#!/bin/bash

# Start Apache Tika server in background
java -jar /opt/tika-server.jar --port 9998 &

# Wait for Tika to start
echo "Waiting for Tika server to start..."
sleep 5

# Start FastAPI application
echo "Starting CIPHER API..."
uvicorn src.main:app --host 0.0.0.0 --port 8000