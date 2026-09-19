FROM node:22.20-alpine3.22

WORKDIR /demo
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY demo.mjs ./

USER node
CMD ["node", "demo.mjs"]
