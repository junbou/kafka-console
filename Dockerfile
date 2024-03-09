FROM node:18-alpine as fe
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
COPY frontend/scripts ./scripts
RUN npm config set registry https://registry.npmmirror.com \
    && npm install
COPY frontend .
RUN NODE_OPTIONS="--max-old-space-size=12288" npm run build

FROM golang:1.21-alpine as be
WORKDIR /app
COPY backend/go.mod backend/go.sum ./
RUN go env -w GOPROXY='https://goproxy.cn, direct' \
    && go mod download -x
COPY backend .
COPY --from=fe /app/build ./pkg/embed/frontend/
RUN CGO_ENABLED=0 go build -ldflags "-w -s" -o console ./cmd/api/main.go

FROM busybox:1.36.1
WORKDIR /app
COPY --from=be /app/console .
EXPOSE 8080
CMD ["/app/console"]
