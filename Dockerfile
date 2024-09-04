FROM golang:1.22-alpine AS builder
RUN apk update && apk add make 
COPY . /src
WORKDIR /src
RUN make

FROM alpine:3.20
COPY --from=builder /src/check-password-strength /usr/local/bin/
ENTRYPOINT [ "/usr/local/bin/check-password-strength" ]