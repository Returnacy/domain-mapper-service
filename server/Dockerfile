FROM node:20-alpine AS base

WORKDIR /app

# Install dependencies
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm i --omit=dev; fi && npm cache clean --force

# Build stage (with dev deps)
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm i; fi
COPY tsconfig.json ./tsconfig.json
COPY src ./src
COPY domain-mapping.json ./domain-mapping.json
RUN npm run build

# Runtime stage
FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
ENV DOMAIN_MAPPING_FILE=/app/domain-mapping.json
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY --from=build /app/domain-mapping.json ./domain-mapping.json
EXPOSE 4005
CMD ["node", "dist/src/app.js"]
