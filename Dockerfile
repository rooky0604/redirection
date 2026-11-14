FROM node:20-alpine

# Police pour l'image du programme (planning -> Discord), rendue par sharp.
RUN apk add --no-cache fontconfig font-dejavu

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund

COPY server.js ./
COPY .env.example ./
COPY data ./data

ENV NODE_ENV=production
ENV PORT=3000
ENV DATA_DIR=/app/data

VOLUME ["/app/data"]

EXPOSE 3000

CMD ["node", "server.js"]
