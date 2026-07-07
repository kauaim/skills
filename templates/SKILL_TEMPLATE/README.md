# Skill Title

One paragraph description — what it does and why it's useful.

See `SKILL.md` for the full workflow.

## What's inside

```
SKILL.md            the skill definition Claude reads
scripts/             (if any) supporting scripts
reference/           (if any) longer background material
```

## Installing in Claude Code

1. Unzip/copy this folder into your skills directory:
   - Project-scoped (only this repo): `<your-project>/.claude/skills/skill-name-here/`
   - User-scoped (all projects): `~/.claude/skills/skill-name-here/`
2. Claude Code discovers skills automatically from `SKILL.md`'s frontmatter.

## Installing in Claude Desktop

Copy this folder into the Skills folder under Settings → Capabilities/Skills, so
you end up with `skill-name-here/` containing `SKILL.md` at its root. Restart
Claude Desktop if it doesn't pick up the new skill immediately.

## License

Licensed under [CC BY-NC-SA 4.0](../LICENSE) — free to reuse and adapt, credit
required, non-commercial, share derivatives under the same license.
