# Optional: auto-screen on every file Read (Claude Code hook)

The `guard.py` wrapper is the portable way to screen before ingesting. If you run in
Claude Code (or Cowork), you can also wire a PreToolUse hook so the screen fires
automatically whenever Claude is about to Read a file, with no reliance on the skill
triggering.

## Wire it up

Add this to your `settings.json` (project `.claude/settings.json` or user settings),
pointing at the absolute path of `preread_guard.py`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          { "type": "command", "command": "python3 /ABSOLUTE/PATH/TO/prompt-injection-guard/hooks/preread_guard.py" }
        ]
      }
    ]
  }
}
```

The hook receives the tool event as JSON on stdin (including `tool_input.file_path`),
scans the target file, and surfaces any flags.

## Modes

- Informational (default): flags print to stderr and the Read proceeds, so the agent
  sees the warning and applies the doctrine. This is the safe default.
- Blocking: set `GUARD_BLOCK=1` in the hook environment to exit 2 (block) on a
  high-severity flag, which sends the reason back to Claude for confirmation before the
  file is used.

```json
{ "type": "command", "command": "GUARD_BLOCK=1 python3 /ABSOLUTE/PATH/.../hooks/preread_guard.py" }
```

## Notes

- Exit code contract: 0 lets the Read proceed (stderr is shown); 2 blocks and feeds
  stderr back to Claude as the reason.
- Only text-like and common document extensions are scanned; binaries are skipped.
- Hook configuration details can change between Claude Code versions. If the hook does
  not fire, check the current hooks reference at docs.claude.com and confirm the
  `matcher` and `settings.json` shape for your version.
- The hook is a convenience layer. The load-bearing controls remain the doctrine in
  `SKILL.md` and least privilege; the screen is a tripwire, not a wall.
