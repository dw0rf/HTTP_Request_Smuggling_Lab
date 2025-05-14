# Dockerfile for lab interface
FROM node:16-slim

# Create app directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./
RUN npm install

# Bundle app source
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Expose the port
EXPOSE 8081

# Start the application
CMD ["node", "server.js"]