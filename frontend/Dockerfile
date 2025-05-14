# Frontend Dockerfile - Creates a vulnerable NGINX configuration
FROM nginx:1.21

# Install dependencies for custom NGINX modules if needed
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libpcre3-dev \
    zlib1g-dev \
    libssl-dev \
    netcat \
    && rm -rf /var/lib/apt/lists/*

# Create log directory
RUN mkdir -p /var/log/nginx

# Set working directory
WORKDIR /etc/nginx

# Copy entrypoint script
COPY docker-entrypoint.sh /custom-entrypoint.sh
RUN chmod +x /custom-entrypoint.sh

# The nginx.conf will be mounted as a volume

ENTRYPOINT ["/custom-entrypoint.sh"]
