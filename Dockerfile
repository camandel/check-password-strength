FROM golang:1.16-alpine AS builder
RUN apk update && apk add make 
COPY . /src
WORKDIR /src
RUN make

FROM alpine:3.13
COPY --from=builder /src/check-password-strength /usr/local/bin/
ENTRYPOINT [ "/usr/local/bin/check-password-strength" ]