# Секреты в образ не попадают: копируется только код, а конфигурация приходит
# извне через переменные окружения.

FROM golang:1.25-alpine AS builder

WORKDIR /src

# Сначала манифесты: слой с зависимостями переиспользуется, пока не меняются
# версии. Контракт приходит из прокси модулей по версии из go.mod, поэтому
# копировать его вручную не нужно.
COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/auth-service ./cmd

FROM alpine:3.20

# ca-certificates нужен, если сервис станет обращаться к внешним API.
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 app

WORKDIR /app

COPY --from=builder /out/auth-service /app/auth-service

# Миграции копируются в образ: без них сервис не поднимется, потому что схема
# управляется миграциями, а не вызовами CREATE TABLE в коде.
COPY --from=builder /src/db /app/db

# Файл .env намеренно не копируется: секреты остались бы в слоях образа.
USER app

EXPOSE 50051

ENTRYPOINT ["/app/auth-service"]