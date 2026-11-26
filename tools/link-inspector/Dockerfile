FROM node:22-alpine
WORKDIR /worker
COPY worker.js ./worker.js
USER node
EXPOSE 8080
CMD ["node", "worker.js"]
