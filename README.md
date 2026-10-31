# SinFuga

[Leer en español](README.es.md)

SinFuga stops accidental leaks of secrets and personal data before they reach Claude Code or Codex. It is one Python file with no dependencies, and it has detectors for Latin American identity documents.

> **Status: early version.** Blocking was verified on Windows inside real Codex 0.166.0-alpha.5.1, and inside real Claude Code 2.1.309 against a simulated local model. Other versions may behave differently. It reduces accidents; it does not guarantee that nothing leaks.

## What it blocks

- **Secrets:** AWS, GitHub, OpenAI, Anthropic, Google, Slack and Stripe keys, private keys, JWTs, URLs with passwords, and values assigned to names like `password` or `api_key`.
- **Personal data:** card numbers (Luhn), Brazil's CPF, Chile's RUT, Colombia's NIT and Mexico's CURP. Cédulas and DNIs count only when the text says they are one.
- **Sensitive paths:** `.env`, `.ssh`, cloud credentials and AI tool tokens. `.env.example` is allowed.
- **Files with secrets:** it scans a file's content before the AI reads it, through file tools and commands such as `cat config.py`.

Block messages never repeat the secret, and input SinFuga cannot understand is blocked.

## Install

Requires Python 3.9+ available as `python`.

```bash
git clone <repository-url>
cd sinfuga
python test_sinfuga.py
python sinfuga.py install
```

`install` copies the script to `~/.sinfuga`, adds hooks to `~/.claude/settings.json` and `~/.codex/hooks.json` (keeping a `.bak` copy), and installs the skill and the auditor agent. 

**Codex silently ignores hooks you have not trusted.** Until you open `/hooks` and trust SinFuga, Codex gives no warning and nothing is blocked.

To remove the hooks:

```bash
python sinfuga.py uninstall
```

## Audit a project

```bash
python sinfuga.py scan path/to/project
```

It prints file, line and type, never the value, and exits with 1 if it finds something.

## Exceptions

List files with fake data in `.sinfuga-ignore`, one pattern per line:

```text
# test data
fixtures/*
```

Exceptions apply to reading existing files. They do not apply to prompts or new content, and the AI cannot edit this file.

## Limits

- **It can be evaded.** `cat .e*` or `grep -r key .` pass, because SinFuga does not see command output. Both tools describe hooks as a guardrail, not a complete security boundary.
- **It only knows patterns.** Business strategy, medical notes or names in plain language are not detected, and neither are unlisted key formats.
- **It cannot undo a leak.** If a secret already reached an AI or a repository, revoke it.
- **It only covers Claude Code and Codex.** Browser chats are not covered.
- **It needs Python.** If `python` cannot run, the hook does not block.
- **False positives can happen.** Long numbers can pass a checksum by chance.

## License

[MIT](LICENSE)
