import { useState } from "react";
import type { FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ErrorNotice } from "../components/Feedback";
import { useAuth } from "../context/AuthContext";
import { AuthLayout } from "../layouts/AuthLayout";
import { errorMessage } from "../utils/errors";

const MIN_PASSWORD = 10;

/** Mirrors the server's password policy so problems show before submitting. */
function passwordProblems(password: string): string[] {
  const problems: string[] = [];
  if (password.length < MIN_PASSWORD) problems.push(`at least ${MIN_PASSWORD} characters`);
  if (!/\p{L}/u.test(password)) problems.push("a letter");
  if (!/\d/.test(password)) problems.push("a digit");
  return problems;
}

export function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const problems = passwordProblems(password);
  const canSubmit = fullName.trim() !== "" && email.trim() !== "" && problems.length === 0;

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await register(fullName.trim(), email.trim(), password);
      navigate("/dashboard", { replace: true });
    } catch (caught) {
      setError(errorMessage(caught, "Registration failed. Please try again."));
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout title="Create your account" subtitle="Register to add repositories and track their analysis.">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="full_name" className="mb-1 block text-sm font-medium">
            Full name
          </label>
          <input
            id="full_name"
            className="field"
            value={fullName}
            onChange={(event) => setFullName(event.target.value)}
            autoComplete="name"
            maxLength={100}
            required
            autoFocus
          />
        </div>
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
            maxLength={254}
            required
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
            autoComplete="new-password"
            maxLength={128}
            required
            aria-describedby="password_hint"
          />
          <p id="password_hint" className={`mt-1 text-xs ${password && problems.length ? "text-warn" : "text-muted"}`}>
            {password && problems.length
              ? `Still needs ${problems.join(", ")}.`
              : `At least ${MIN_PASSWORD} characters, with a letter and a digit.`}
          </p>
        </div>
        {error && <ErrorNotice message={error} />}
        <button type="submit" className="btn btn-primary w-full" disabled={submitting || !canSubmit}>
          {submitting ? "Creating account…" : "Create account"}
        </button>
      </form>
      <p className="mt-6 text-sm text-muted">
        Already registered?{" "}
        <Link to="/login" className="font-semibold text-trust hover:underline">
          Sign in
        </Link>
      </p>
    </AuthLayout>
  );
}
