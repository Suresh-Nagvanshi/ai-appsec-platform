/**
 * Centralised Axios instance.
 * Base URL is read from the NEXT_PUBLIC_API_URL env var so
 * both local dev (http://localhost:8000) and production deployments
 * work without code changes.
 *
 * Auth: if NEXT_PUBLIC_API_KEY is set in .env.local, every request
 * automatically carries the X-API-Key header required by the
 * backend API key middleware (backend/auth/api_key.py).
 * Leave the var unset (or set API_KEY_DISABLED=true on the backend)
 * to skip auth during early local development.
 */

import axios from "axios";

const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000",
  timeout: 30_000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Attach X-API-Key to every outgoing request when the env var is present.
// The interceptor is a no-op when NEXT_PUBLIC_API_KEY is undefined so
// dev environments without the key set continue to work unchanged.
api.interceptors.request.use((config) => {
  const apiKey = process.env.NEXT_PUBLIC_API_KEY;
  if (apiKey) {
    config.headers["X-API-Key"] = apiKey;
  }
  return config;
});

export default api;
