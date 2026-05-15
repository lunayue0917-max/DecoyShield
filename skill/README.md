# decoyshield · Claude Code skill

This directory contains a [Claude Code](https://claude.com/claude-code)
skill that lets you add DecoyShield protection to any Python web project
with one command: type `/decoyshield` in Claude Code and it will wire
the honeypot into the current codebase.

## Install

Copy the `decoyshield/` directory into your Claude Code skills folder:

### macOS / Linux

```bash
mkdir -p ~/.claude/skills
cp -r decoyshield ~/.claude/skills/
```

### Windows (PowerShell)

```powershell
$dest = "$env:USERPROFILE\.claude\skills"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
Copy-Item -Recurse decoyshield $dest
```

Restart Claude Code (or `/reload`) and the skill should appear in the
available-skills list.

## Use

Inside any Python web project, type:

```
/decoyshield
```

The skill will:

1. Detect your web framework (currently Flask is supported; others will
   be flagged).
2. Add `decoyshield` to your dependency manifest.
3. Insert the one-line middleware integration in your app entry point.
4. Update `.gitignore` so capture logs aren't committed.
5. Print the dashboard URL and a test command.

The skill never starts your server, never installs packages without
asking, and never overwrites existing routes.

## How is this different from running decoyshield directly?

The Python package is the runtime. This skill is just the Claude Code
operator that knows the right way to wire it into a foreign codebase —
useful when you want Claude to add the protection without you reading
the README first.
