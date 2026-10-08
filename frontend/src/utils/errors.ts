import axios from "axios";

interface FieldError {
  loc?: string[];
  msg?: string;
}

/** Turn any failure from the API client into one sentence a person can act on. */
export function errorMessage(error: unknown, fallback = "Something went wrong. Please try again."): string {
  if (axios.isAxiosError(error)) {
    if (!error.response) {
      return "The server could not be reached. Check that the backend is running.";
    }
    const detail: unknown = (error.response.data as { detail?: unknown } | undefined)?.detail;
    if (typeof detail === "string" && detail) return detail;
    if (Array.isArray(detail) && detail.length > 0) {
      return (detail as FieldError[])
        .map((item) => {
          const field = item.loc?.filter((part) => part !== "body").join(".");
          const message = (item.msg ?? "is invalid").replace(/^Value error,\s*/i, "");
          return field ? `${field}: ${message}` : message;
        })
        .join(" · ");
    }
    if (error.response.status === 429) return "Too many attempts. Wait a minute and try again.";
    if (error.response.status >= 500) return "The server reported an error. Please try again shortly.";
  }
  return fallback;
}
