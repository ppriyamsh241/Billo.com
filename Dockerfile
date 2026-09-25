FROM node:22-alpine
WORKDIR /app
COPY server/package*.json ./server/
RUN cd server && npm ci --omit=dev
COPY server ./server
COPY database ./database
ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000
CMD ["node", "server/server.js"]
