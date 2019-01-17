# 1. Backed
FROM golang:alpine AS build-go
ENV D=/go/src/github.com/lmacko/contiv-ui
ADD ./backend $D/backend
ADD ./vendor $D/vendor
RUN cd $D/backend && go build -o backend app.go && cp backend /tmp/

# 2. Angular UI
FROM node:8.14-alpine AS build-node
RUN apk --no-cache add python2

# This is required due to this issue: https://github.com/nodejs/node-gyp/issues/1236#issuecomment-309401410
RUN mkdir /root/.npm-global && npm config set prefix '/root/.npm-global'
ENV PATH="/root/.npm-global/bin:${PATH}"
ENV NPM_CONFIG_LOGLEVEL warn
ENV NPM_CONFIG_PREFIX=/root/.npm-global
RUN npm install -g npm@latest
RUN npm install -g @angular/cli@7.0.2
# deps
RUN mkdir -p /src/ui
ADD ./ui/package.json /src/ui/
RUN cd /src/ui && npm install
# build
ADD ./ui /src/ui
RUN cd /src/ui && ng build --prod --aot --output-hashing=all

# 3. Final Image
FROM alpine
RUN apk --no-cache add ca-certificates
WORKDIR /app/server/
COPY --from=build-go /tmp/backend /app/server/
COPY --from=build-node /src/ui/dist/contiv-vpp-ui /app/server/static/
#ADD ui/index.html /app/server/static/index.html
EXPOSE 9500
CMD ["./backend"]
