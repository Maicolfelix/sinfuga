#!/usr/bin/env python3
"""SinFuga: frena secretos y datos personales antes de que lleguen a Claude Code o Codex.

Sin argumentos funciona como hook: lee JSON por stdin y responde JSON para detener.
Explica el riesgo y deja decidir a la persona: `sinfuga permitir` solo vale en un mensaje suyo.
  sinfuga.py scan RUTA   revisa archivos actuales (exit 1 si encuentra algo)
  sinfuga.py audit RUTA|URL   informe de un proyecto o repositorio, con su historial de git
  sinfuga.py install     instala hooks, skill y agente en este usuario
  sinfuga.py uninstall   quita hooks, skill y agente
Nunca imprime el secreto: solo el tipo de hallazgo y el archivo.
"""
import fnmatch
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
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
    "URL con contraseña": r"\b[a-z][a-z0-9+.-]*://[^\s:/@$<{]+:[^\s:/@$<{]+@",
    "CURP de México": r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[A-Z0-9]\d\b",
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
    r"|\.sinfuga-ignore$|\.sinfuga/permisos\.json$|[^/]*\.(?:pem|pfx|p12)$)"
)
SHELL_TOKEN = re.compile(r"""[^\s"'|;&<>()=,@]+""")
PATCH_FILE = re.compile(r"^\*\*\* \w+ File: (.+)$", re.M)
MAX_FILE = 2_000_000
MAX_TARGETS = 50
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
IGNORE_FILE = ".sinfuga-ignore"
PERMIT_PROMPT = re.compile(r"(?i)^\s*sinfuga permitir:")
PERMIT_CODE = re.compile(r"(?i)^\s*sinfuga permitir ([0-9a-f]{6})\s*$")
PERMIT_SECONDS = 600
RISKS = (
    (("tarjeta",), "Con un número de tarjeta alguien puede intentar compras a tu nombre."),
    (("documento", "CURP", "CPF", "RUT", "NIT"),
     "Con un documento de identidad alguien puede suplantarte o cometer fraudes, y no se cambia como una contraseña."),
    (("ruta sensible",), "Este archivo suele guardar contraseñas, llaves o sesiones activas: quien lo lea puede entrar a tus cuentas."),
    (("clave", "token", "API key", "llave", "JWT", "contraseña"),
     "Quien tenga esta credencial puede entrar a tu cuenta o tus servidores, robar información o generar cobros."),
)
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
    "número de tarjeta": (re.compile(r"(?<![\d.-])[3-6](?:[ -]?\d){12,18}(?![\d-])"), valid_card),
    "CPF de Brasil": (re.compile(r"(?<![\d.])\d{3}\.\d{3}\.\d{3}-\d{2}(?!\d)"), valid_cpf),
    "RUT de Chile": (re.compile(r"(?<![\d.])(\d{1,2}\.\d{3}\.\d{3})-([\dkK])\b"), valid_rut),
    "NIT de Colombia": (re.compile(r"(?i)\bNIT\D{0,6}(\d{3}\.?\d{3}\.?\d{3})-?(\d)\b"), valid_nit),
}


def find_secrets(text):
    found = {name for name, rx in RULES.items() if rx.search(text)}
    for m in ASSIGNMENT.finditer(text):
        value = m.group(1)
        if re.search(r"[A-Za-z]", value) and re.search(r"\d", value) and not PLACEHOLDER.search(value):
            found.add("contraseña o secreto")
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
        prompt = event.get("prompt", "")
        permit = PERMIT_CODE.match(prompt)
        if permit:
            grant_permit(permit.group(1).lower())
        if permit or PERMIT_PROMPT.match(prompt):
            return []
        return [f"el mensaje contiene: {name}" for name in sorted(find_secrets(prompt))]

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
    return [] if problems and use_permit(action_code(event)) else problems


def permits_path():
    return Path.home() / ".sinfuga" / "permisos.json"


def load_permits():
    try:
        permits = json.loads(permits_path().read_text("utf-8"))
        return {code: end for code, end in permits.items() if end > time.time()}
    except (OSError, ValueError, AttributeError, TypeError):
        return {}


def save_permits(permits):
    permits_path().parent.mkdir(exist_ok=True)
    permits_path().write_text(json.dumps(permits), "utf-8")


def grant_permit(code):
    save_permits({**load_permits(), code: time.time() + PERMIT_SECONDS})


def use_permit(code):
    """Consume el permiso: vale una sola vez."""
    permits = load_permits()
    found = permits.pop(code, None) is not None
    if found:
        save_permits(permits)
    return found


def action_code(event):
    """Identifica esta accion exacta: si la IA cambia algo, el permiso ya no vale."""
    action = [event.get("session_id"), event.get("tool_name"), event.get("tool_input")]
    return hashlib.sha256(json.dumps(action, sort_keys=True).encode()).hexdigest()[:6]


def explain(event, problems):
    risks = [text for names, text in RISKS if any(n in p for n in names for p in problems)]
    risks.append(
        "Lo que envías a una IA sale de tu equipo y puede quedar en registros e historiales. "
        "Si llega a un repositorio o enlace público, cualquiera puede copiarlo, y borrarlo después no lo recupera."
    )
    if event.get("hook_event_name") == "UserPromptSubmit":
        proceed = "Si decides continuar, vuelve a enviar tu mensaje empezando por: sinfuga permitir:"
    else:
        proceed = (
            f"Si decides continuar, escribe tú este mensaje: sinfuga permitir {action_code(event)}\n"
            f"Vale una sola vez, solo para esta acción y durante {PERMIT_SECONDS // 60} minutos. "
            "Para la IA: muestra este aviso completo al usuario. No puedes aprobarlo ni rodearlo."
        )
    return "\n".join([
        "SinFuga detuvo esto antes de que saliera de tu equipo. "
        "No es un límite de tu plan ni de la IA: es una protección local y la decisión es tuya.",
        "", "Qué encontró:", *(f"- {p}" for p in problems),
        "", "Por qué es peligroso:", *(f"- {r}" for r in risks),
        "", "Qué puedes hacer:",
        "- Lo más seguro: quita el dato, usa una variable de entorno o datos falsos.",
        f"- {proceed}",
        "- Si este dato ya se compartió, cámbialo o revócalo. Si es un falso positivo, lista el archivo en .sinfuga-ignore.",
    ])


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
    reason = explain(event, problems)
    # JSON y no exit 2: PowerShell -Command convierte el 2 en 1, que no bloquea.
    if event.get("hook_event_name") == "UserPromptSubmit":
        print(json.dumps({"decision": "block", "reason": reason}))
    else:
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }}))


def walk_files(root):
    for folder, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in names:
            yield Path(folder, name)


def scan(root):
    root = Path(root)
    base = root.parent if root.is_file() else root
    files = [root] if root.is_file() else walk_files(root)
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


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, encoding="utf-8", errors="replace")


def history_blobs(repo):
    """Da (sha, ruta, contenido) de cada archivo de cualquier commit, una vez por version."""
    paths = {}
    for line in git(repo, "rev-list", "--objects", "--all").stdout.splitlines():
        sha, _, path = line.partition(" ")
        if path:
            paths.setdefault(sha, path)
    # Un archivo como stdin evita el bloqueo de escribir y leer la misma tuberia.
    with tempfile.TemporaryFile() as shas:
        shas.write("".join(f"{sha}\n" for sha in paths).encode())
        shas.seek(0)
        batch = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"], stdin=shas, stdout=subprocess.PIPE)
        for sha, path in paths.items():
            header = batch.stdout.readline().split()
            if len(header) != 3:
                continue
            data = batch.stdout.read(int(header[2]) + 1)[:-1]  # +1: salto de linea tras cada objeto
            if header[1] == b"blob":
                yield sha, path, data
        batch.wait()


def audit_repo(repo, patterns):
    """Hallazgos del historial como {(tipo, ruta): (linea, estado, sha)}."""
    head = {line.split()[2] for line in git(repo, "ls-tree", "-r", "HEAD").stdout.splitlines() if line.split()[1] == "blob"}
    found = {}

    def add(rule, path, line, sha):
        state = "actual" if sha in head else "historial"
        if (rule, path) not in found or state == "actual":
            found[rule, path] = (line, state, sha)

    for sha, path, data in history_blobs(repo):
        if any(fnmatch.fnmatch(path, p) for p in patterns):
            continue
        if SENSITIVE_PATH.search(path) and not path.endswith(IGNORE_FILE):
            add("ruta sensible", path, 0, sha)
        if len(data) > MAX_FILE or b"\0" in data[:8000]:
            continue
        for number, line in enumerate(data.decode("utf-8", "ignore").splitlines(), 1):
            for rule in find_secrets(line):
                add(rule, path, number, sha)
    return found


def audit_folder(root, repo, found):
    """Agrega lo que esta en disco y aun no entro a git."""
    for path in walk_files(root):
        rel = path.relative_to(root).as_posix()
        if ignored(path, root):
            continue
        try:
            lines = path.read_text("utf-8", "ignore").splitlines() if path.stat().st_size <= MAX_FILE else []
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for rule in find_secrets(line):
                found.setdefault((rule, rel), (number, "local" if repo else "archivo", None))


def gitignore_gaps(repo):
    # ponytail: busca el texto del patron; `git check-ignore` necesitaria copia de trabajo.
    text = git(repo, "show", "HEAD:.gitignore").stdout
    return [p for p in (".env", "*.pem") if p not in text]


def severity(rule, state):
    if state == "local" or rule == "gitignore incompleto":
        return "MEDIO"
    return "ALTO" if any(n in rule for names, _ in RISKS[:2] for n in names) else "CRÍTICO"


def risk_of(rule):
    if rule == "gitignore incompleto":
        return "Un `git add .` podría subir credenciales sin que te des cuenta."
    return next((text for names, text in RISKS if any(n in rule for n in names)), "")


def print_report(target, found, gaps, commits, repo=None):
    print(f"Auditoría de SinFuga: {target}")
    print(f"Commits revisados: {commits}. El informe nunca muestra los valores.\n")
    groups = {}
    for (rule, path), (line, state, sha) in found.items():
        groups.setdefault((severity(rule, state), rule), []).append((path, line, state, sha))
    if gaps:
        groups["MEDIO", "gitignore incompleto"] = [(".gitignore", 0, f"falta: {', '.join(gaps)}", None)]
    if not groups:
        print("No se encontró nada. Esto no garantiza que no haya fugas: solo revisa patrones conocidos.")
        return 0
    order = {"CRÍTICO": 0, "ALTO": 1, "MEDIO": 2}
    print(f"Hallazgos: {sum(len(v) for v in groups.values())}\n")
    for (level, rule), places in sorted(groups.items(), key=lambda g: (order[g[0][0]], g[0][1])):
        print(f"[{level}] {rule}")
        print(f"  Por qué importa: {risk_of(rule)}")
        for path, line, state, sha in sorted(places):
            where = f"{path}:{line}" if line else path
            print(f"  - {where} ({STATES.get(state, state)}{commit_note(repo, sha)})")
        print()
    print("Qué hacer:")
    print("- Revoca y reemplaza cada credencial marcada como actual o historial: borrarla no basta.")
    print("- Si el repositorio es público, considera expuesto lo que esté en git: copias y forks pueden conservarlo.")
    print("- Mueve los secretos a variables de entorno y limpia el historial si guardaba datos personales.")
    print("- Algunos hallazgos pueden ser datos de ejemplo o de prueba: verifica cada uno antes de actuar.")
    print("- Solo se revisan patrones conocidos: un informe corto no garantiza que no haya más fugas.")
    return 1


STATES = {
    "actual": "está en la versión actual",
    "historial": "ya no está, pero sigue en el historial",
    "local": "solo en tu equipo, sin subir a git",
    "archivo": "en un archivo de la carpeta",
}


def commit_note(repo, sha):
    if not sha or not repo:
        return ""
    commits = git(repo, "log", "--all", "--format=%h", f"--find-object={sha}").stdout.split()
    return f", commit {commits[-1]}" if commits else ""


REMOTE = re.compile(r"^(?:https://[^\s@/]+/\S+|ssh://git@\S+|git@[\w.-]+:\S+)$")


def audit_git(target, repo, root):
    # Un repositorio ajeno no decide que se le revisa: su .sinfuga-ignore no cuenta.
    patterns = ignore_patterns(str(root)) if root else ()
    found = audit_repo(repo, patterns)
    if root:
        audit_folder(root, True, found)
    commits = git(repo, "rev-list", "--all", "--count").stdout.strip() or "0"
    has_head = git(repo, "rev-parse", "--verify", "-q", "HEAD").returncode == 0
    return print_report(target, found, gitignore_gaps(repo) if has_head else [], commits, repo)


def audit(target):
    sys.stdout.reconfigure(errors="replace")
    if REMOTE.match(target) and not Path(target).exists():
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https:ssh",
               "GIT_SSH_COMMAND": "ssh -oBatchMode=yes"}
        with tempfile.TemporaryDirectory() as folder:
            # --mirror no crea copia de trabajo ni ejecuta nada del repositorio; solo se leen datos.
            clone = subprocess.run(["git", "clone", "--quiet", "--mirror", "--", target, folder],
                                   env=env, capture_output=True, timeout=900)
            if clone.returncode:
                print("No se pudo clonar. Revisa la URL, o si es privado tus permisos de git.", file=sys.stderr)
                return 2
            return audit_git(target, folder, None)
    root = Path(target)
    if not root.is_dir():
        print("Indica una carpeta existente o una URL https:// o git@ sin credenciales.", file=sys.stderr)
        return 2
    top = git(root, "rev-parse", "--show-toplevel")
    if top.returncode:
        found = {}
        audit_folder(root, False, found)
        return print_report(target, found, [], 0)
    return audit_git(target, top.stdout.strip(), Path(top.stdout.strip()))


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


def skill_dirs():
    home = Path.home()
    return [home / ".claude" / "skills" / "sinfuga", home / ".agents" / "skills" / "sinfuga"]


def agent_files():
    home = Path.home()
    return [home / ".claude" / "agents" / "sinfuga-auditor.md", home / ".codex" / "agents" / "sinfuga_auditor.toml"]


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
    for path in skill_dirs():
        shutil.copytree(here / "skills" / "sinfuga", path, dirs_exist_ok=True)
    for path in agent_files():
        path.parent.mkdir(exist_ok=True)
        shutil.copy2(here / "agents" / path.name, path)
    print("Instalado. ATENCION: Codex ignora en silencio este hook hasta que lo apruebes en /hooks.")


def main():
    args = sys.argv[1:]
    if not args:
        hook()
    elif args[0] == "scan" and len(args) == 2:
        sys.exit(scan(args[1]))
    elif args[0] == "audit" and len(args) == 2:
        sys.exit(audit(args[1]))
    elif args == ["install"]:
        install()
    elif args == ["uninstall"]:
        for path in config_files():
            if path.exists():
                set_hooks(path, None)
        for path in skill_dirs():
            shutil.rmtree(path, ignore_errors=True)
        for path in agent_files():
            path.unlink(missing_ok=True)
        print("SinFuga desinstalado.")
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
