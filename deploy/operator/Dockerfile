FROM golang:1.24-bookworm AS build
WORKDIR /source
COPY providers/terraform/go.mod providers/terraform/go.sum ./
RUN go mod download
COPY providers/terraform/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /asterius-operator ./cmd/asterius-operator

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /asterius-operator /asterius-operator
USER 65532:65532
ENTRYPOINT ["/asterius-operator"]
