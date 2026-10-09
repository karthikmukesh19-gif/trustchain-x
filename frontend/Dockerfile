FROM node:22-alpine AS build
WORKDIR /app
# Once a package-lock.json has been generated and committed, switch this to
# `COPY package.json package-lock.json ./` and `npm ci` for reproducible builds.
COPY package.json package-lock.json* ./
# With the committed lockfile the build installs exactly the recorded versions (npm ci verifies their integrity hashes).
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi
COPY . .
RUN npm run build

# Unprivileged nginx: runs as a non-root user and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
