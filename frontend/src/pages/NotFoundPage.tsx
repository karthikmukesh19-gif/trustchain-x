import { Link } from "react-router-dom";

export function NotFoundPage() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center px-4 text-center">
      <div className="eyebrow">404</div>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">Page not found</h1>
      <p className="mt-2 max-w-sm text-sm text-muted">This address does not match any page in TrustChain-X.</p>
      <Link to="/dashboard" className="btn btn-primary mt-6">
        Go to dashboard
      </Link>
    </div>
  );
}
