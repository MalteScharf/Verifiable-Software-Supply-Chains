FROM node:20-alpine

WORKDIR /app

ARG CODECOV_NONCE
ENV CODECOV_NONCE=${CODECOV_NONCE}

COPY package.json ./
RUN npm install --omit=dev

COPY server.js ./

EXPOSE 3000

CMD ["node", "server.js"]
