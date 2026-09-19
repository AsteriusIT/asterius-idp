# Financial webapp

The Compose `financial` profile builds this React application and serves it at
`https://localhost/financial/`. Its assets and React Router routes use that
prefix, while browser API calls go through `https://localhost/financial-api`.

```sh
docker compose -f deploy/compose/docker-compose.yml \
  --profile financial up --build -d
```

The API callback returns to `/financial/` on the same HTTPS origin. Keeping the
callback redirect chain on that origin is required by the authorization
interaction's `form-action` Content Security Policy.

For standalone Vite development, point the UI at a locally running API:

```sh
npm install
VITE_API_URL=http://localhost:4000 npm run dev
```

The webapp is deliberately a thin React Router UI. OAuth is started by the
API BFF; tokens stay server-side.
