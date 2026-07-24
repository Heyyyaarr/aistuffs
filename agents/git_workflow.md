# Git Workflow Agent

Repeatable steps for branching, committing, pushing, and opening PRs.

## Steps

1. **Check current state**
   - `git status` — see modified/untracked files
   - `git diff` — review unstaged changes
   - `git log --oneline -5` — recent commits for context

2. **Create branch**
   - `git checkout -b <type>/<short-description>` (types: `fix`, `feature`, `chore`, `docs`, `refactor`)
   - Branch from `main` (or current base)

3. **Stage and commit**
   - `git add <files>` — stage intended files only (check with `git diff --cached`)
   - `git commit -m "<type>: <imperative description>"` — first line ≤ 72 chars
   - Verify no secrets or unintended files in the commit

4. **Push**
   - `git push -u origin <branch-name>`

5. **Create PR**
   - `gh pr create --title "<type>: <description>" --body "<summary of changes, how to test, config notes>"`

6. **Open in browser**
   - `open <pr-url>` (macOS) or `xdg-open <pr-url>` (Linux)

## Commit message types

| Type | Usage |
|------|-------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `refactor` | Code restructuring, no functional change |
| `chore` | Build, CI, or tooling |

## Rules

- First line ≤ 72 characters
- Imperative mood ("add" not "added")
- Never commit secrets or unintended files
- Always review `git diff` before staging