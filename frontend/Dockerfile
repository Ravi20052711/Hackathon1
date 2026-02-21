FROM node:20-alpine

WORKDIR /app

# Copy package files first for caching
COPY package.json package-lock.json* ./
RUN npm install

# Copy rest of frontend
COPY . .

EXPOSE 5173

# Vite dev server with host flag for Docker
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
