# Intelligent API Security Analyzer — Analyst Workspace

The frontend is a React and TypeScript analyst workspace for reviewing API security scans, findings, endpoint correlations, benchmark research, and exports. It talks to the FastAPI service through the Vite `/api` and `/health` development proxies.

## Run locally

Prerequisites: Node.js 20 or newer and a running backend at `http://localhost:8000`.

```bash
npm install
npm run dev
```

Open `http://127.0.0.1:5173`. Vite binds to loopback by default and proxies `/api` and `/health` to the local backend. LAN access to the development server is not a supported mode; do not override the host binding while `LOCAL_DEV_AUTH_BYPASS=true`. The application has no user-account or sign-up flow. On the loopback development server, the example configuration can show **Local access** without a token. Otherwise choose **Connect API** in the header and enter a backend-configured X-API-Key or Bearer token. The key is held in session storage for the active browser session.

## Verify changes

```bash
npm test
npm run lint
npm run build
```

`npm test` runs the frontend unit and integration tests, `npm run lint` checks the React and TypeScript source, and `npm run build` performs the production TypeScript and Vite build.

The production build is written to `dist/`. Configure the deployed frontend host to route `/api` and `/health` to the backend service; the Vite proxy only applies during local development.
