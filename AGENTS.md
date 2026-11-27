# AGENTS.md — Project conventions

## Code style (matches .editorconfig)

- 4-space indentation, no tabs
- Keep a newline at the end of the file
- UTF-8 with BOM
- CRLF line endings
- using directives: `System` first, remaining namespaces in alphabetical order
- Run `dotnet format` before committing to auto-fix style

## Git commits

- Do NOT commit unless the user explicitly asks for it
- Commit messages in English
- Conventional Commits format, Include a body no footers

## Documentation sync

- When modifying SshServerLoader/Program.cs, keep the example code in both README.md and README_zh-cn.md in sync.
