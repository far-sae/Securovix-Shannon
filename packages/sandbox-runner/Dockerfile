FROM node:20-alpine
RUN apk add --no-cache docker-cli
WORKDIR /app
COPY packages/sandbox-runner /app
USER root
EXPOSE 8080
CMD ["node", "server.mjs"]
