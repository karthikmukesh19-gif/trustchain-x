import axios from "axios";

const TOKEN_KEY = "trustchain.token";

/**
 * The token lives in sessionStorage: it survives a reload but is dropped when
 * the tab closes. Storage can be unavailable (private mode, blocked site
 * data), in which case the session simply lasts until the page is reloaded.
 */
let memoryToken: string | null = null;

export function getToken(): string | null {
  if (memoryToken) return memoryToken;
  try {
    memoryToken = sessionStorage.getItem(TOKEN_KEY);
  } catch {
    memoryToken = null;
  }
  return memoryToken;
}

export function setToken(token: string | null): void {
  memoryToken = token;
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Storage unavailable: the in-memory copy is used for this page load.
  }
}

type UnauthorisedHandler = () => void;
let onUnauthorised: UnauthorisedHandler | null = null;

/** Registered by the auth context so an expired session returns to the login page. */
export function setUnauthorisedHandler(handler: UnauthorisedHandler | null): void {
  onUnauthorised = handler;
}

export const api = axios.create({
  baseURL: "/api",
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.request.use((config) => {
  const token = getToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error: unknown) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      const url = error.config?.url ?? "";
      const isCredentialCheck = url.startsWith("/auth/login") || url.startsWith("/auth/register");
      if (!isCredentialCheck && getToken()) {
        setToken(null);
        onUnauthorised?.();
      }
    }
    return Promise.reject(error);
  },
);
