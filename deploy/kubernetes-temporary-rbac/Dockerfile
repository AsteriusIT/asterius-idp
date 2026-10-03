FROM golang:1.24-bookworm AS build
WORKDIR /source
COPY providers/terraform/go.mod providers/terraform/go.sum ./
RUN go mod download
COPY providers/terraform/ ./
RUN CGO_ENABLED=0 go build -trimpath -o /asterius-jit-rbac ./cmd/asterius-jit-rbac

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /asterius-jit-rbac /asterius-jit-rbac
USER 65532:65532
ENTRYPOINT ["/asterius-jit-rbac"]
