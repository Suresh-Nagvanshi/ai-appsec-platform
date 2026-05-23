/**
 * Centralised Axios instance.
 * Base URL is read from the NEXT_PUBLIC_API_URL env var so
 * both local dev (http://localhost:8000) and production deployments
 * work without code changes.
 */

import axios from "axios";

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  timeout: 30_000,
  headers: {
    "Content-Type": "application/json",
  },
});

export default api;
