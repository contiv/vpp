# 1) BUILD API
FROM golang:alpine AS build-go
#RUN apk --no-cache add git bzr mercurial
ENV D=/go/src/github.com/lmacko/contiv-ui
# deps - using the closest thing to an official dependency tool: https://github.com/golang/dep
#RUN go get -u github.com/golang/dep/...
#ADD ./api/Gopkg.* $D/api/
#RUN cd $D && dep ensure -v --vendor-only
# build
ADD ./backend $D/backend
ADD ./vendor $D/vendor
RUN cd $D/backend && go build -o api app.go && cp api /tmp/


# 2) BUILD UI
#FROM node:alpine AS build-node
#RUN apk --no-cache add python2

# This is required due to this issue: https://github.com/nodejs/node-gyp/issues/1236#issuecomment-309401410
#RUN mkdir /root/.npm-global && npm config set prefix '/root/.npm-global'
#ENV PATH="/root/.npm-global/bin:${PATH}"
#ENV NPM_CONFIG_LOGLEVEL warn
#ENV NPM_CONFIG_PREFIX=/root/.npm-global
#RUN npm install -g npm@latest
# cli@1.3.X doesn't work
#RUN npm install -g @angular/cli@1.2.7
# deps
#RUN mkdir -p /src/ui
#ADD ./ui/package.json /src/ui/
#RUN cd /src/ui && npm install
# build
#ADD ./ui /src/ui
#RUN cd /src/ui && ng build --prod --aot


# 3) BUILD FINAL IMAGE
FROM alpine
RUN apk --no-cache add ca-certificates
WORKDIR /app/server/
COPY --from=build-go /tmp/api /app/server/
#COPY --from=build-node /src/ui/dist /app/server/static/
ADD ui /app/server/static
EXPOSE 9500
CMD ["./api"]