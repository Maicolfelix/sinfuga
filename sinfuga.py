#!/usr/bin/env python3
"""SinFuga: frena secretos y datos personales antes de que lleguen a Claude Code o Codex.

Sin argumentos funciona como hook: lee JSON por stdin y responde JSON para bloquear.
  sinfuga.py scan RUTA   audita archivos (exit 1 si encuentra algo)
  sinfuga.py install     instala hooks, skill y agente en este usuario
  sinfuga.py uninstall   quita los hooks
Nunca imprime el secreto: solo el tipo de hallazgo y el archivo.
"""
import fnmatch
import functools
import json
import os
import re
import shutil
import sys
from pathlib import Path

# ponytail: patrones a mano para no exigir dependencias; integrar Gitleaks si hacen falta sus 150+ reglas.
RULES = {
    "clave AWS": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    "token GitHub": r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b",
    "API key OpenAI/Anthropic": r"\bsk-[A-Za-z0-9_-]{20,}",
    "API key Google": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "token Slack": r"\bxox[abprs]-[0-9A-Za-z-]{10,}",
    "clave Stripe": r"\b[sr]k_live_[0-9a-zA-Z]{16,}",
    "llave privada": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "JWT": r"\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}",
    "URL con contrasena": r"\b[a-z][a-z0-9+.-]*://[^\s:/@$<{]+:[^\s:/@$<{]+@",
    "CURP de Mexico": r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b",
    # Sin digito de control: solo cuenta si el texto dice que es un documento.
    "documento de identidad": r"(?i)\b(?:c[eé]dula(?: de ciudadan[ií]a)?|c\.c\.|dni|documento de identidad)\D{0,12}\d(?:[.\s]?\d){5,9}\b",
}
RULES = {name: re.compile(rx) for name, rx in RULES.items()}
ASSIGNMENT = re.compile(
    r"""(?i)(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|contrase[ñn]a|clave)"""
    r"""["']?\s*[:=]\s*["']?([^\s"',;]{8,})"""
)
PLACEHOLDER = re.compile(r"(?i)[$<{(]|example|changeme|placeholder|your|xxxx")

SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|/)(?:"
    r"\.env(?!\.(?:example|sample|template)$)(?:\.[\w.-]+)?$"
    r"|\.ssh/|id_(?:rsa|dsa|ecdsa|ed25519)(?!\.pub)|\.aws/credentials|\.kube/config"
    r"|\.docker/config\.json|\.git-credentials|\.netrc|\.pgpass"
    r"|\.codex/auth\.json|\.claude/\.credentials\.json|login data"
    r"|\.sinfuga-ignore$|[^/]*\.(?:pem|pfx|p12)$)"
)
SHELL_TOKEN = re.compile(r"""[^\s"'|;&<>()=,@]+""")
PATCH_FILE = re.compile(r"^\*\*\* \w+ File: (.+)$", re.M)
MAX_FILE = 2_000_000
MAX_TARGETS = 50
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
IGNORE_FILE = ".sinfuga-ignore"
NIT_WEIGHTS = (3, 7, 13, 17, 19, 23, 29, 37, 41)


def digits_of(text):
    return [int(c) for c in re.sub(r"\D", "", text)]


def valid_card(m):
    total = 0
    for i, n in enumerate(reversed(digits_of(m.group()))):
        n *= 2 if i % 2 else 1
        total += n - 9 if n > 9 else n
    return total % 10 == 0


def valid_cpf(m):
    d = digits_of(m.group())
    if len(set(d)) == 1:
        return False
    return all(sum(v * (n + 1 - i) for i, v in enumerate(d[:n])) * 10 % 11 % 10 == d[n] for n in (9, 10))


def valid_rut(m):
    body = digits_of(m.group(1))
    remainder = 11 - sum(v * (2 + i % 6) for i, v in enumerate(reversed(body))) % 11
    return m.group(2).upper() == {10: "K", 11: "0"}.get(remainder, str(remainder))


def valid_nit(m):
    remainder = sum(w * v for w, v in zip(NIT_WEIGHTS, reversed(digits_of(m.group(1))))) % 11
    return int(m.group(2)) == (remainder if remainder < 2 else 11 - remainder)


# Formatos con digito de control: se valida para no bloquear cualquier numero.
CHECKED = {
    "numero de tarjeta": (re.compile(r"(?<![\d.-])[3-6](?:[ -]?\d){12,18}(?![\d-])"), valid_card),
    "CPF de Brasil": (re.compile(r"(?<![\d.])\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)"), valid_cpf),
    "RUT de Chile": (re.compile(r"(?<![\d.])(\d{1,2}\.\d{3}\.\d{3})-([\dkK])\b"), valid_rut),
    "NIT de Colombia": (re.compile(r"(?i)\bNIT\D{0,6}(\d{3}\.?\d{3}\.?\d{3})-?(\d)\b"), valid_nit),
}


def find_secrets(text):
    found = {name for name, rx in RULES.items() if rx.search(text)}
    for m in ASSIGNMENT.finditer(text):
        value = m.group(1)
        if re.search(r"[A-Za-z]", value) and re.search(r"\d", value) and not PLACEHOLDER.search(value):
            found.add("contrasena o secreto")
    found.update(name for name, (rx, valid) in CHECKED.items() if any(valid(m) for m in rx.finditer(text)))
    return found


@functools.lru_cache(maxsize=8)
def ignore_patterns(base):
    try:
        lines = Path(base, IGNORE_FILE).read_text("utf-8").splitlines()
    except OSError:
        return ()
    return tuple(p for p in map(str.strip, lines) if p and not p.startswith("#"))


def ignored(path, base):
    """Cierto si el archivo esta en .sinfuga-ignore. No aplica a mensajes ni a lo que se escribe."""
    try:
        rel = Path(path).resolve().relative_to(Path(base).resolve()).as_posix()
    except (OSError, ValueError):
        return False
    return any(fnmatch.fnmatch(rel, p) for p in ignore_patterns(str(base)))


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from strings(v)


def read_targets(tool_name, tool_input):
    """Rutas que la herramienta va a tocar, sin mirar el contenido que escribe."""
    targets = [tool_input[k] for k in ("file_path", "path", "notebook_path") if isinstance(tool_input.get(k), str)]
    command = " ".join(strings(tool_input.get("command", "")))
    targets += (PATCH_FILE if tool_name == "apply_patch" else SHELL_TOKEN).findall(command)
    return targets


def scan_file(path):
    try:
        if path.is_file() and path.stat().st_size <= MAX_FILE:
            return find_secrets(path.read_text("utf-8", "ignore"))
    except (OSError, ValueError):
        pass
    return set()


def check(event):
    """Devuelve la lista de problemas del evento; vacia si puede continuar."""
    if event.get("hook_event_name") == "UserPromptSubmit":
        return [f"el mensaje contiene: {name}" for name in sorted(find_secrets(event.get("prompt", "")))]

    tool_input = event.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {"command": tool_input}
    problems = [f"la accion contiene: {n}" for n in sorted(find_secrets(" ".join(strings(tool_input))))]
    cwd = event.get("cwd") or "."
    for target in read_targets(event.get("tool_name", ""), tool_input)[:MAX_TARGETS]:
        if SENSITIVE_PATH.search(target.strip().replace("\\", "/")):
            problems.append(f"ruta sensible: {target}")
            continue
        path = Path(cwd, target)
        if not ignored(path, cwd):
            problems += [f"{target} contiene: {n}" for n in sorted(scan_file(path))]
    return problems


def hook():
    # Falla cerrado: una entrada que no se entiende no pasa.
    try:
        event = json.loads(sys.stdin.buffer.read().decode("utf-8", "replace"))
        problems = check(event)
    except Exception as e:
        sys.stderr.write(f"SinFuga bloqueo por error interno ({type(e).__name__})\n")
        sys.exit(2)
    if not problems:
        return
    reason = "SinFuga bloqueo esto:\n- " + "\n- ".join(problems)
    # JSON y no exit 2: PowerShell -Command convierte el 2 en 1, que no bloquea.
    if event.get("hook_event_name") == "UserPromptSubmit":
        print(json.dumps({"decision": "block", "reason": reason}))
    else:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}))


def scan(root):
    root = Path(root)
    base = root.parent if root.is_file() else root
    files = [root] if root.is_file() else (
        Path(d, f) for d, dirs, names in os.walk(root)
        if not dirs.__setitem__(slice(None), [x for x in dirs if x not in SKIP_DIRS])
        for f in names
    )
    hits = 0
    for path in files:
        if ignored(path, base):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as lines:
                for number, line in enumerate(lines, 1):
                    for name in sorted(find_secrets(line)):
                        print(f"{path}:{number}: {name}")
                        hits += 1
        except OSError:
            pass
    print(f"{hits} hallazgo(s)")
    return 1 if hits else 0


def config_files():
    home = Path.home()
    return [home / ".claude" / "settings.json", home / ".codex" / "hooks.json"]


def set_hooks(path, entry):
    """Quita las entradas de SinFuga y agrega `entry`, guardando copia .bak."""
    config = json.loads(path.read_text("utf-8")) if path.exists() else {}
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
    hooks = config.setdefault("hooks", {})
    for event in ("UserPromptSubmit", "PreToolUse"):
        kept = [g for g in hooks.get(event, []) if "sinfuga" not in json.dumps(g)]
        hooks[event] = kept + ([entry] if entry else [])
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        del config["hooks"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", "utf-8")


def install():
    here = Path(__file__).resolve().parent
    home = Path.home()
    # Copia estable: los hooks siguen vivos aunque se borre la carpeta del proyecto.
    target = home / ".sinfuga" / "sinfuga.py"
    target.parent.mkdir(exist_ok=True)
    if Path(__file__).resolve() != target:
        shutil.copy2(__file__, target)
    # `python "ruta"` funciona igual en bash, cmd y PowerShell; las barras / evitan escapes.
    entry = {"hooks": [{"type": "command", "command": f'python "{target.as_posix()}"', "timeout": 10}]}
    for path in config_files():
        set_hooks(path, entry)
    for tool in (".claude", ".codex"):
        shutil.copytree(here / "skills" / "sinfuga", home / tool / "skills" / "sinfuga", dirs_exist_ok=True)
    (home / ".claude" / "agents").mkdir(exist_ok=True)
    shutil.copy2(here / "agents" / "sinfuga-auditor.md", home / ".claude" / "agents")
    print("Instalado. ATENCION: Codex ignora en silencio este hook hasta que lo apruebes en /hooks.")


def main():
    args = sys.argv[1:]
    if not args:
        hook()
    elif args[0] == "scan" and len(args) == 2:
        sys.exit(scan(args[1]))
    elif args == ["install"]:
        install()
    elif args == ["uninstall"]:
        for path in config_files():
            if path.exists():
                set_hooks(path, None)
        print("Hooks quitados.")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
