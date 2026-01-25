# Dockerfile demonstrating security issues

FROM node:18

# DK-002: Running as root user
USER root

WORKDIR /app

# DK-003: Remote script execution in RUN
RUN curl -fsSL https://install.example.com/setup.sh | bash

COPY . .

RUN npm install

EXPOSE 3000

CMD ["node", "server.js"]
