FROM node:24.11.1-trixie-slim
WORKDIR /app
ENV GRAPHILE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY server.mjs ./
USER node
EXPOSE 4000
CMD ["node", "server.mjs"]
