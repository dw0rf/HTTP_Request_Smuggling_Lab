#!/bin/sh

# Wait for backend to be available
echo "Waiting for backend service..."
while ! nc -z backend 3000; do
  sleep 1
done
echo "Backend is up and running!"

# Start NGINX
exec nginx -g "daemon off;"
