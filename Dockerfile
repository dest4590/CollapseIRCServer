FROM golang:1.25.1-alpine AS builder

WORKDIR /app

COPY go.mod go.sum* ./

RUN go mod download

COPY . /app

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o irc ./src

FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/irc .

COPY --from=builder /app/banned_users.txt* ./

EXPOSE 1338

CMD ["./irc"]