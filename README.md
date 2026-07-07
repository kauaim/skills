# Skills

A collection of Claude skills (for Claude Code and Claude Desktop), free to
download and adapt under the terms in [LICENSE](LICENSE) (CC BY-NC-SA 4.0 —
credit required, non-commercial, share-alike).

Each skill lives in its own top-level folder with a `SKILL.md` and its own
`README.md` covering installation.

## Skills

- [`prompt-injection-guard/`](prompt-injection-guard/) — screens third-party or
  untrusted documents (PDFs, Word/Excel, email, web pages, pasted text) for
  prompt-injection and hidden-instruction attacks before Claude acts on their
  contents, and enforces the rule that ingested content is data, never
  instructions.

More skills will be added over time, one folder each.

## Installing a skill

See the individual skill's `README.md` for exact steps. In general:

- **Claude Code**: drop the skill folder into `.claude/skills/` (project-scoped)
  or `~/.claude/skills/` (user-scoped, all projects).
- **Claude Desktop**: drop the skill folder into the Skills folder under
  Settings → Capabilities/Skills.

## License

CC BY-NC-SA 4.0 — see [LICENSE](LICENSE). You're welcome to use, adapt, and
share these skills; please give credit, don't use them commercially without
permission, and share any derivatives under the same license.
