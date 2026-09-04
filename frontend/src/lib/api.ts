/**
 * Centralised Axios instance.
 * Browser requests use the same-origin Next.js proxy. The proxy injects the
 * server-only BACKEND_API_KEY before forwarding requests to FastAPI.
 */

import axios from "axios";

const api = axios.create({
  baseURL: "/api/backend",
  timeout: 30_000,
  headers: {
    "Content-Type": "application/json",
  },
});

export default api;
