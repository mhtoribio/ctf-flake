#!/usr/bin/env python3
import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VERBOSE = 0


def shlex_quote(s: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=+,-]+", s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def format_cmd(cmd: list[str]) -> str:
    return " ".join(shlex_quote(x) for x in cmd)


def run(cmd, *, check=True, capture_output=True, text=True, **kwargs):
    if VERBOSE >= 1:
        print(f"+ {format_cmd(cmd)}", file=sys.stderr)

    res = subprocess.run(
        cmd,
        check=False,
        capture_output=capture_output,
        text=text,
        **kwargs,
    )

    if capture_output:
        if VERBOSE >= 2 and res.stdout:
            print("----- stdout -----", file=sys.stderr)
            print(res.stdout, end="" if res.stdout.endswith("\n") else "\n", file=sys.stderr)
        if VERBOSE >= 3 and res.stderr:
            print("----- stderr -----", file=sys.stderr)
            print(res.stderr, end="" if res.stderr.endswith("\n") else "\n", file=sys.stderr)

    if check and res.returncode != 0:
        raise subprocess.CalledProcessError(
            res.returncode,
            cmd,
            output=res.stdout,
            stderr=res.stderr,
        )

    return res


def require_tool(name: str) -> None:
    if shutil.which(name) is None:
        print(f"error: required tool not found: {name}", file=sys.stderr)
        sys.exit(1)


def docker_build(context: Path, dockerfile: Path, tag: str, build_args: list[str]) -> None:
    cmd = [
        "docker", "build",
        "-f", str(dockerfile),
        "-t", tag,
    ]
    for arg in build_args:
        cmd += ["--build-arg", arg]
    cmd += [str(context)]
    run(cmd, capture_output=False)


def docker_run_bg(image: str) -> str:
    # Keep the container alive so we can docker exec / docker cp from it.
    res = run([
        "docker", "run",
        "-d",
        "--entrypoint", "sh",
        image,
        "-lc", "while :; do sleep 3600; done",
    ])
    container_id = res.stdout.strip()
    if not container_id:
        raise RuntimeError("docker run returned empty container id")
    return container_id


def docker_rm(container_id: str) -> None:
    run(["docker", "rm", "-f", container_id], check=False)


def docker_rmi(image: str) -> None:
    run(["docker", "rmi", "-f", image], check=False)


def docker_image_inspect_json(image: str) -> dict:
    res = run(["docker", "image", "inspect", image])
    arr = json.loads(res.stdout)
    if not arr:
        raise RuntimeError("docker image inspect returned no objects")
    return arr[0]


def shell_quote_single(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


def docker_exec_sh(container_id: str, script: str, *, check=True):
    return run(
        ["docker", "exec", container_id, "sh", "-lc", script],
        check=check,
    )


def jail_inner_path(path: str, jailed_root: str) -> str:
    if path == jailed_root:
        return "/"
    if not path.startswith(jailed_root + "/"):
        raise RuntimeError(f"Path {path} is not under jailed root {jailed_root}")
    return path[len(jailed_root):]


def split_command_tokens(value) -> list[str]:
    if isinstance(value, list):
        return [str(token) for token in value if token]
    if isinstance(value, str):
        try:
            return shlex.split(value)
        except ValueError:
            return [value]
    return []


def config_exec_tokens(image_inspect_obj: dict) -> list[str]:
    cfg = image_inspect_obj.get("Config", {})
    entrypoint = cfg.get("Entrypoint") or []
    cmd = cfg.get("Cmd") or []

    candidates: list[str] = []
    candidates.extend(split_command_tokens(entrypoint))
    candidates.extend(split_command_tokens(cmd))

    return candidates


def unwrap_command_tokens(tokens: list[str]) -> list[str]:
    current = list(tokens)

    while current:
        head = current[0]
        base = Path(head).name

        if head == "exec":
            current = current[1:]
            continue

        if base in {"sh", "bash", "ash", "dash"} and len(current) >= 3:
            shell_flag = current[1]
            if shell_flag.startswith("-") and "c" in shell_flag[1:]:
                inner_tokens = split_command_tokens(current[2])
                if inner_tokens:
                    current = inner_tokens
                    continue

        break

    return current


def infer_socat_exec_target(tokens: list[str]) -> str | None:
    tokens = unwrap_command_tokens(tokens)
    if not tokens:
        return None

    if Path(tokens[0]).name != "socat":
        return None

    for token in tokens[1:]:
        if not token.upper().startswith("EXEC:"):
            continue

        payload = token[len("EXEC:"):]
        if not payload:
            continue

        program = payload.split(",", 1)[0]
        if not program:
            continue

        return program

    return None


def detect_pwnred_jail_from_dockerfile(dockerfile: Path) -> bool:
    text = dockerfile.read_text(encoding="utf-8", errors="ignore")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if re.search(r"^\s*FROM\s+.*pwn\.red/jail\b", line, re.IGNORECASE):
            return True

        if re.search(r"^\s*COPY\s+.*\s+/srv\s*$", line, re.IGNORECASE):
            return True

    return False


def detect_pwnred_jail_from_image(image_inspect_obj: dict) -> bool:
    return any(
        isinstance(token, str) and (token == "/jail/run" or token.startswith("/jail/"))
        for token in config_exec_tokens(image_inspect_obj)
    )


def is_pwnred_jail_mode(image_inspect_obj: dict, dockerfile: Path | None = None) -> bool:
    if dockerfile is not None and detect_pwnred_jail_from_dockerfile(dockerfile):
        return True
    if detect_pwnred_jail_from_image(image_inspect_obj):
        return True
    return False


def path_exists_exec(container_id: str, path: str, *, jailed_root: str | None = None) -> bool:
    if jailed_root is not None and (path == jailed_root or path.startswith(jailed_root + "/")):
        inner_path = jail_inner_path(path, jailed_root)
        quoted_inner = shell_quote_single(inner_path)
        quoted_root = shell_quote_single(jailed_root)
        script = rf'''
set -eu
chroot {quoted_root} /usr/bin/test -x {quoted_inner}
'''
    else:
        quoted = shell_quote_single(path)
        script = rf'''
set -eu
test -x {quoted}
'''
    res = docker_exec_sh(container_id, script, check=False)
    return res.returncode == 0


def choose_target_binary(
    container_id: str,
    image_inspect_obj: dict,
    explicit_binary: str | None,
    jail_mode: bool,
) -> str:
    if explicit_binary:
        return explicit_binary

    if jail_mode:
        for candidate in ["/srv/app/run", "/srv/app/chal", "/srv/app/pwn"]:
            if path_exists_exec(container_id, candidate, jailed_root="/srv"):
                return candidate

        raise RuntimeError(
            "Detected pwn.red jail image, but could not find an executable challenge binary. "
            "Pass it explicitly with --binary /srv/app/..."
        )

    tokens = unwrap_command_tokens(config_exec_tokens(image_inspect_obj))
    socat_target = infer_socat_exec_target(tokens)
    if socat_target:
        return socat_target

    for token in tokens:
        if not token:
            continue
        if token.startswith("-"):
            continue
        return token

    raise RuntimeError(
        "Could not infer target binary from image config. "
        "Pass it explicitly with --binary /path/to/program"
    )


def resolve_binary_path(container_id: str, binary: str, *, jailed_root: str | None = None) -> str:
    if jailed_root is not None and (binary == jailed_root or binary.startswith(jailed_root + "/")):
        inner_binary = jail_inner_path(binary, jailed_root)
        quoted_inner = shell_quote_single(inner_binary)
        quoted_root = shell_quote_single(jailed_root)
        script = rf'''
set -eu
root={quoted_root}
p="$(chroot "$root" /usr/bin/readlink -f -- {quoted_inner} 2>/dev/null || true)"
[ -n "$p" ]
printf '%s\n' "$root$p"
'''
        res = docker_exec_sh(container_id, script, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"Could not resolve binary inside jailed root: {binary}")
        return res.stdout.strip()

    quoted = shell_quote_single(binary)
    script = rf'''
set -eu

bin={quoted}

if [ "${{bin#/}}" != "$bin" ] && [ -e "$bin" ]; then
    readlink -f "$bin" 2>/dev/null || printf '%s\n' "$bin"
    exit 0
fi

if printf '%s' "$bin" | grep -q '/'; then
    if [ -e "$bin" ]; then
        readlink -f "$bin" 2>/dev/null || printf '%s\n' "$bin"
        exit 0
    fi
fi

p="$(command -v -- "$bin" || true)"
if [ -n "$p" ]; then
    readlink -f "$p" 2>/dev/null || printf '%s\n' "$p"
    exit 0
fi

exit 1
'''
    res = docker_exec_sh(container_id, script, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"Could not resolve binary inside container: {binary}")
    return res.stdout.strip()


def ldd_paths(container_id: str, binary_path: str, *, jailed_root: str | None = None) -> list[str]:
    paths: set[str] = set()

    if jailed_root is not None:
        if not binary_path.startswith(jailed_root + "/"):
            raise RuntimeError(
                f"Binary path {binary_path} is not under jailed root {jailed_root}"
            )

        inner_binary = jail_inner_path(binary_path, jailed_root)
        quoted_inner = shell_quote_single(inner_binary)
        quoted_root = shell_quote_single(jailed_root)
        script = rf'''
set -eu
chroot {quoted_root} /usr/bin/ldd {quoted_inner}
'''
    else:
        quoted = shell_quote_single(binary_path)
        script = rf'''
set -eu
ldd {quoted}
'''

    res = docker_exec_sh(container_id, script, check=False)
    out = (res.stdout or "") + "\n" + (res.stderr or "")
    normalized_lines = [line.strip() for line in out.splitlines() if line.strip()]

    for line in normalized_lines:
        if line == "statically linked" or "not a dynamic executable" in line or "not a valid dynamic program" in line:
            raise RuntimeError(
                f"Target binary is not a dynamic executable: {binary_path}"
            )

    if res.returncode != 0:
        if jailed_root is not None:
            raise RuntimeError(f"ldd failed for jailed binary {binary_path}:\n{out}")
        raise RuntimeError(f"ldd failed for {binary_path}:\n{out}")

    for line in normalized_lines:
        m = re.search(r'=>\s+(\S+)\s+\(', line)
        if m:
            p = m.group(1)
            if p != "not":
                paths.add((jailed_root or "") + p)
            continue

        m = re.match(r'(/[^ ]+)\s+\(', line)
        if m:
            paths.add((jailed_root or "") + m.group(1))
            continue

    paths.add(binary_path)
    return sorted(paths)


def resolve_real_path(container_id: str, path: str, *, jailed_root: str | None = None) -> str:
    if jailed_root is not None and (path == jailed_root or path.startswith(jailed_root + "/")):
        inner_path = jail_inner_path(path, jailed_root)
        quoted_inner = shell_quote_single(inner_path)
        quoted_root = shell_quote_single(jailed_root)
        script = rf'''
set -eu
root={quoted_root}
p="$(chroot "$root" /usr/bin/readlink -f -- {quoted_inner})"
printf '%s\n' "$root$p"
'''
        res = docker_exec_sh(container_id, script, check=False)
        if res.returncode != 0:
            raise RuntimeError(f"Could not resolve real path for {path} inside jailed root")
        return res.stdout.strip()

    quoted = shell_quote_single(path)
    script = rf'''
set -eu
p={quoted}
readlink -f -- "$p"
'''
    res = docker_exec_sh(container_id, script, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"Could not resolve real path for {path}")
    return res.stdout.strip()

def docker_cp_out(container_id: str, container_path: str, out_dir: Path) -> Path:
    rel = container_path.lstrip("/")
    host_path = out_dir / rel
    host_path.parent.mkdir(parents=True, exist_ok=True)

    tmpdir = Path(tempfile.mkdtemp(prefix="extract-lib-"))
    try:
        tmp_target = tmpdir / Path(container_path).name
        run(["docker", "cp", f"{container_id}:{container_path}", str(tmp_target)], capture_output=False)

        if tmp_target.is_dir():
            raise RuntimeError(f"Expected file, got directory when copying {container_path}")

        shutil.move(str(tmp_target), str(host_path))
        return host_path
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def main() -> int:
    global VERBOSE

    parser = argparse.ArgumentParser(
        description="Build a Docker image, run a temporary container, inspect a target binary with ldd inside it, and extract its libraries."
    )
    parser.add_argument("--context", default=".", help="Docker build context")
    parser.add_argument("--dockerfile", default="Dockerfile", help="Path to Dockerfile")
    parser.add_argument("--tag", default="extract-libs-temp:latest", help="Temporary image tag")
    parser.add_argument("--binary", help="Target binary inside container. If omitted, inferred from ENTRYPOINT/CMD.")
    parser.add_argument("--out", default="extracted-libs", help="Output directory")
    parser.add_argument(
        "--keep-alive",
        action="store_true",
        help="Build and start the container, then wait for manual inspection before cleaning up.",
    )
    parser.add_argument(
        "--build-arg",
        action="append",
        default=[],
        help="Build arg in KEY=VALUE form. Can be passed multiple times.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON summary at the end.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity: -v commands, -vv stdout, -vvv stderr.",
    )
    args = parser.parse_args()

    VERBOSE = args.verbose

    require_tool("docker")

    context = Path(args.context).resolve()
    dockerfile = Path(args.dockerfile).resolve()
    out_dir = Path(args.out).resolve()

    if not dockerfile.exists():
        print(f"error: Dockerfile does not exist: {dockerfile}", file=sys.stderr)
        return 1

    out_dir.mkdir(parents=True, exist_ok=True)

    container_id = None
    copied: list[dict] = []

    try:
        docker_build(context, dockerfile, args.tag, args.build_arg)

        image_inspect_obj = docker_image_inspect_json(args.tag)
        container_id = docker_run_bg(args.tag)

        if args.keep_alive:
            print(f"[+] container running: {container_id}")
            print(f"[+] image tag: {args.tag}")
            input("ready to close?")
            return 0

        jail_mode = is_pwnred_jail_mode(image_inspect_obj, dockerfile)
        jailed_root = "/srv" if jail_mode else None

        if jail_mode:
            print("[+] detected pwn.red jail mode")

        target = choose_target_binary(container_id, image_inspect_obj, args.binary, jail_mode)

        resolved_binary = resolve_binary_path(container_id, target, jailed_root=jailed_root)

        print(f"[+] target binary: {target}")
        if jailed_root is not None:
            print(f"[+] jailed root: {jailed_root}")
        print(f"[+] resolved path: {resolved_binary}")

        deps = ldd_paths(container_id, resolved_binary, jailed_root=jailed_root)

        resolved_map: dict[str, str] = {}
        real_files: list[str] = []
        seen_real: set[str] = set()

        for dep in deps:
            real = resolve_real_path(container_id, dep, jailed_root=jailed_root)
            resolved_map[dep] = real
            if real not in seen_real:
                seen_real.add(real)
                real_files.append(real)

        print("[+] files to extract:")
        for dep in deps:
            real = resolved_map[dep]
            if dep == real:
                print(f"    {real}")
            else:
                print(f"    {dep} -> {real}")

        for real in real_files:
            host_path = docker_cp_out(container_id, real, out_dir)
            copied.append({
                "container_path": real,
                "host_path": str(host_path),
            })

        if args.json:
            print(json.dumps({
                "image_tag": args.tag,
                "binary": target,
                "resolved_binary": resolved_binary,
                "copied": copied,
            }, indent=2))
        else:
            print(f"[+] extracted {len(copied)} files to {out_dir}")

    finally:
        if container_id is not None:
            docker_rm(container_id)
        docker_rmi(args.tag)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
