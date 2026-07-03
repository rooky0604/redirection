FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache certbot

COPY package.json ./
COPY server.js ./
COPY .env.example ./
COPY data ./data

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

VOLUME ["/app/data"]

EXPOSE 80
EXPOSE 443
EXPOSE 3000

CMD ["node", "server.js"]
