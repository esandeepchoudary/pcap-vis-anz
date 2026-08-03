# tours/

Each file here is one hand-authored (or human-confirmed) feature walk — see
the project README's "Configuring tours and auth" section for the YAML shape
and a worked example.

Quick path to your first tour, from inside Claude Code:

1. Implement or point at a feature you want documented.
2. `/docsolace:document propose <slug> "<description>"` — drafts a candidate
   tour by actually driving the app (`status: proposed`, `maturity: draft`).
3. Review the draft, fill in anything left as a TODO, then flip
   `status: confirmed` yourself — nothing here does that for you.
4. `/docsolace:document <slug>` — captures screenshots and generates its page.
5. `/docsolace:document init-site` once you've got at least one generated
   page, to scaffold a browsable docs site.

**Security reminder:** never commit `.env` or anything under
`.docsolace/artifacts/.auth/` — both can hold live credentials or session
cookies. This project's `.gitignore` already excludes them.
