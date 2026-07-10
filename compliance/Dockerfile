FROM node:18-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001

# Copy package manifests
COPY package*.json ./

# Install dependencies
RUN npm install --production && npm cache clean --force

# Copy source code
COPY . .

# Create logs directory with proper permissions
RUN mkdir -p /app/logs/compliance && chown -R nodejs:nodejs /app

# Create certs directory
RUN mkdir -p /etc/certs /etc/secrets && chown -R nodejs:nodejs /etc/certs /etc/secrets

# Switch to non-root user
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('fs').existsSync('/app/logs/compliance/audit.json') || process.exit(1)"

# Expose metrics port
EXPOSE 9090

# Run compliance replay script
CMD ["node", "src/compliance-replay.js"]