FROM node:22.20-alpine3.22
WORKDIR /apps/sso-demo
COPY examples/sso-demo/package.json examples/sso-demo/package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY examples/sso-demo/demo.mjs ./
WORKDIR /apps/playground-protocols
COPY examples/playground-protocols/package.json examples/playground-protocols/lab.mjs ./
RUN ln -s ../sso-demo/node_modules node_modules
USER node
CMD ["node", "lab.mjs"]
