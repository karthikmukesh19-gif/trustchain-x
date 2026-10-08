import { useState } from "react";
import type { FormEvent } from "react";
import { FiPlus } from "react-icons/fi";

import { createProject } from "../services/projects";
import { errorMessage } from "../utils/errors";
import type { Project } from "../utils/types";
import { ErrorNotice } from "./Feedback";

const GITHUB_URL = /^https:\/\/(www\.)?github\.com\/[A-Za-z0-9-]+\/[A-Za-z0-9._-]+\/?$/;

/** Suggest a project name from the repository part of the URL. */
function nameFromUrl(url: string): string {
  const match = url.trim().match(/github\.com\/[^/]+\/([^/]+?)(?:\.git)?\/?$/);
  return match ? match[1] : "";
}

export function ProjectForm({ onCreated, onCancel }: { onCreated: (project: Project) => void; onCancel?: () => void }) {
  const [url, setUrl] = useState("");
  const [name, setName] = useState("");
  const [nameEdited, setNameEdited] = useState(false);
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmedUrl = url.trim();
  const urlLooksValid = GITHUB_URL.test(trimmedUrl);
  const showUrlHint = trimmedUrl.length > 0 && !urlLooksValid;

  function handleUrl(value: string) {
    setUrl(value);
    if (!nameEdited) setName(nameFromUrl(value));
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const project = await createProject({
        name: name.trim(),
        repository_url: trimmedUrl,
        description: description.trim(),
      });
      onCreated(project);
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="card space-y-4 p-5" noValidate>
      <div>
        <h2 className="text-base font-semibold">Register a repository</h2>
        <p className="mt-0.5 text-sm text-muted">Public GitHub repositories are supported.</p>
      </div>

      <div>
        <label htmlFor="repository_url" className="mb-1 block text-sm font-medium">
          GitHub repository URL
        </label>
        <input
          id="repository_url"
          className="field font-mono"
          placeholder="https://github.com/owner/repository"
          value={url}
          onChange={(event) => handleUrl(event.target.value)}
          autoComplete="off"
          spellCheck={false}
          maxLength={200}
          required
          aria-describedby={showUrlHint ? "repository_url_hint" : undefined}
          aria-invalid={showUrlHint}
        />
        {showUrlHint && (
          <p id="repository_url_hint" className="mt-1 text-xs text-warn">
            Use the form https://github.com/owner/repository
          </p>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="project_name" className="mb-1 block text-sm font-medium">
            Project name
          </label>
          <input
            id="project_name"
            className="field"
            value={name}
            onChange={(event) => {
              setName(event.target.value);
              setNameEdited(true);
            }}
            maxLength={120}
            required
          />
        </div>
        <div>
          <label htmlFor="project_description" className="mb-1 block text-sm font-medium">
            Description <span className="font-normal text-faint">(optional)</span>
          </label>
          <input
            id="project_description"
            className="field"
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            maxLength={1000}
          />
        </div>
      </div>

      {error && <ErrorNotice message={error} />}

      <div className="flex items-center gap-2">
        <button type="submit" className="btn btn-primary" disabled={submitting || !urlLooksValid || !name.trim()}>
          <FiPlus aria-hidden />
          {submitting ? "Registering…" : "Register project"}
        </button>
        {onCancel && (
          <button type="button" className="btn btn-secondary" onClick={onCancel} disabled={submitting}>
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}
