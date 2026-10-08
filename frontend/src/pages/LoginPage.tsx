import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

import { ErrorNotice } from "../components/Feedback";
import { useAuth } from "../context/AuthContext";
import { AuthLayout } from "../layouts/AuthLayout";
import { errorMessage } from "../utils/errors";

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const from = (location.state as { from?: string } | null)?.from;
  // Only ever return to a path inside this application.
  const destination = from && from.startsWith("/") && !from.startsWith("//") ? from : "/dashboard";

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      navigate(destination, { replace: true });
    } catch (caught) {
      setError(errorMessage(caught, "Sign-in failed. Please try again."));
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout title="Sign in" subtitle="Use the account you registered with.">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="email" className="mb-1 block text-sm font-medium">
            Email
          </label>
          <input
            id="email"
            type="email"
            className="field"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
            required
            autoFocus
          />
        </div>
        <div>
          <label htmlFor="password" className="mb-1 block text-sm font-medium">
            Password
          </label>
          <input
            id="password"
            type="password"
            className="field"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
          />
        </div>
        {error && <ErrorNotice message={error} />}
        <button type="submit" className="btn btn-primary w-full" disabled={submitting || !email.trim() || !password}>
          {submitting ? "Signing in…" : "Sign in"}
        </button>
      </form>
      <p className="mt-6 text-sm text-muted">
        No account yet?{" "}
        <Link to="/register" className="font-semibold text-trust hover:underline">
          Create one
        </Link>
      </p>
    </AuthLayout>
  );
}
