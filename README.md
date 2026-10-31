# SinFuga

[Leer en español](README.es.md)

SinFuga stops accidental leaks of secrets and personal data before they reach Claude Code or Codex. It is one Python file with no dependencies, and it has detectors for Latin American identity documents.

> **Status: early version.** Blocking was verified on Windows inside real Codex 0.166.0-alpha.5.1, and inside real Claude Code 2.1.309 against a simulated local model. Other versions may behave differently. It reduces accidents; it does not guarantee that nothing leaks.

## What it blocks

- **Secrets:** AWS, GitHub, OpenAI, Anthropic, Google, Slack and Stripe keys, private keys, JWTs, URLs with passwords, and values assigned to names like `password` or `api_key`.
- **Personal data:** card numbers (Luhn), Brazil's CPF, Chile's RUT, Colombia's NIT and Mexico's CURP. Cédulas and DNIs count only when the text says they are one.
- **Sensitive paths:** `.env`, `.ssh`, cloud credentials and AI tool tokens. `.env.example` is allowed.
- **Files with secrets:** it scans a file's content before the AI reads it, through file tools and commands such as `cat config.py`.

Notices never repeat the secret, and input SinFuga cannot understand is blocked.

## You decide

SinFuga is not a limit of your plan or of the AI. It is a local protection: it explains what it found, why it is dangerous, and lets you choose.

- **Safest option:** remove the data, or use an environment variable or fake values.
- **Continue with a message:** send it again starting with `sinfuga permitir:`.
- **Continue with an action:** type the code from the notice, such as `sinfuga permitir 1a2b3c`. It works once, only for that exact action, for 10 minutes.

Only a message typed by a person counts, so the AI cannot approve itself through its tools. Hooks are not a security boundary, though: an AI with unrestricted shell access could still try to work around them. Notices are in Spanish for now.

## What's included

| Piece | Claude Code | Codex | What it does |
|---|---|---|---|
| Hook | Yes | Yes | Stops the data, explains the risk and asks for your decision. This is the only piece that blocks. |
| `sinfuga` skill | Yes | Yes | Teaches the AI how to handle notices and run audits. |
| Auditor agent | `sinfuga-auditor` | `sinfuga_auditor` | Runs `audit` on a project or repository and summarizes it, read-only by instruction. |

The skill and the agent are instructions the AI can ignore. In real Codex they were tested with a real model from a temporary project. In real Claude Code, loading was verified with a simulated model, but not how a real model behaves with them.

Use them by asking, for example: "Have sinfuga_auditor audit this project", or `$sinfuga` in Codex.

## Install

Requires Python 3.9+ available as `python`.

```bash
git clone https://github.com/Maicolfelix/sinfuga.git
cd sinfuga
python test_sinfuga.py
python sinfuga.py install
```

`install` copies the script to `~/.sinfuga`, adds hooks to `~/.claude/settings.json` and `~/.codex/hooks.json` (keeping a `.bak` copy), and installs the skill and the auditor agent in each tool's user folder. 

**Codex silently ignores hooks you have not trusted.** Until you open `/hooks` and trust SinFuga, Codex gives no warning and nothing is blocked.

To remove the hooks, the skill and the agent:

```bash
python sinfuga.py uninstall
```

## Audit a project or repository

```bash
python sinfuga.py audit path/to/project
python sinfuga.py audit https://github.com/owner/repo
```

`audit` reviews the current version, the full git history and files on disk that were never committed, so it also finds secrets that were deleted but remain in the history. The report groups findings by severity with file, line, commit, why it matters and what to do. It never shows the values.

- It exits with 0 if it finds nothing, 1 if it finds something and 2 on error.
- Private repositories use your own git access. URLs containing credentials are refused.
- The target repository's `.sinfuga-ignore` is not honored for URLs.
- Some findings can be example or test data, so verify each one.
- Audit only repositories you own or are allowed to review.

For a quick check of current files only:

```bash
python sinfuga.py scan path/to/project
```

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
- **Allowing is your responsibility.** Once you allow something, it leaves your computer as usual. The allow flow was verified in real Claude Code with a simulated model, not in real Codex.
- **It needs Python.** If `python` cannot run, the hook does not block.
- **False positives can happen.** Long numbers can pass a checksum by chance.

## License

[MIT](LICENSE)
