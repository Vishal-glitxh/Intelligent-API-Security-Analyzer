# Intelligent API Security Analyzer — Analyst Workspace

The frontend is a React and TypeScript analyst workspace for reviewing API security scans, findings, endpoint correlations, benchmark research, and exports. It talks to the FastAPI service through the Vite `/api` and `/health` development proxies.

## Run locally

Prerequisites: Node.js 20 or newer and a running backend at `http://localhost:8000`.

```bash
npm install
npm run dev
```

Open `http://localhost:5173`. Configure the API key from the header when the service requires authentication. The key is held in session storage for the active browser session.

## Verify changes

```bash
npm test
npm run lint
npm run build
```

`npm test` runs the frontend unit and integration tests, `npm run lint` checks the React and TypeScript source, and `npm run build` performs the production TypeScript and Vite build.

The production build is written to `dist/`. Configure the deployed frontend host to route `/api` and `/health` to the backend service; the Vite proxy only applies during local development.
