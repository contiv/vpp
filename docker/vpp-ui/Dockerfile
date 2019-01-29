# 1. Backend
FROM golang:1.10.7-alpine3.8 as builder
ENV CGO_ENABLED=0
RUN apk add --update git make
COPY . /go/src/github.com/contiv/vpp
WORKDIR /go/src/github.com/contiv/vpp
RUN make contiv-ui-backend

# 2. Angular UI
FROM node:8.14-alpine AS frontend
RUN apk --no-cache add python2

# This is required due to this issue: https://github.com/nodejs/node-gyp/issues/1236#issuecomment-309401410
RUN mkdir /root/.npm-global && npm config set prefix '/root/.npm-global'
ENV PATH="/root/.npm-global/bin:${PATH}"
ENV NPM_CONFIG_LOGLEVEL warn
ENV NPM_CONFIG_PREFIX=/root/.npm-global

RUN npm install -g npm@latest
RUN npm install -g @angular/cli@7.0.2
RUN mkdir -p /src/ui
ADD ./ui/package.json /src/ui/
RUN cd /src/ui && npm install
ADD ./ui /src/ui
RUN cd /src/ui && ng build --prod --aot --output-hashing=all

# 3. Final Image
FROM alpine:3.8
RUN apk --no-cache add ca-certificates
WORKDIR /app/server/
COPY --from=builder /go/src/github.com/contiv/vpp/cmd/contiv-ui-backend /app/server/
COPY --from=frontend /src/ui/dist/contiv-vpp-ui /app/server/static/
EXPOSE 9500
CMD ["./contiv-ui-backend"]