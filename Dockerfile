FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache tzdata

COPY package.json ./
COPY server.js ./

ENV TZ=Asia/Shanghai

EXPOSE 3002

CMD ["node", "server.js"]
