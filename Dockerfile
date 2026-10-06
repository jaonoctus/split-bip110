FROM node:22.22.3-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npx tsc && npm prune --omit=dev

FROM node:22.22.3-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
# Scan files and output folders are written to the working directory; mount it with -v
# to keep them. Sticky and world-writable (like /tmp) so it also works without a mount,
# whether running as the default user or with --user.
RUN install -d -m 1777 /data
WORKDIR /data
USER node
ENTRYPOINT ["node", "/app/dist/index.js"]
