FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund \
    && npm cache clean --force

COPY src ./src

ENV NODE_ENV=production
EXPOSE 4000
USER node
CMD ["node", "src/server.mjs"]
