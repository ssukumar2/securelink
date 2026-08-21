#!/usr/bin/env python3
"""
Builds and runs every standalone test_*.cpp file in src/, using the
exact source file list and link flags documented in each file's own
"// Build:" comment -- so the comment stays the single source of truth,
never duplicated here.

Each source file is compiled with the compiler that actually matches
its language (gcc for .c, g++ for .cpp) rather than blindly running the
documented command as one g++ invocation. Some .c files here use valid-
C-but-not-valid-C++ constructs (a goto crossing a variable
initialization in sl_aead.c is the one that bit us) -- compiling with
the right tool per file avoids that entirely instead of working around
it case by case.

Every binary runs under a timeout. A test that hangs is exactly the
kind of bug this project has actually found before (a self-deadlock in
HealthCheck::render()) -- a hang must be treated as a failure, not left
to block the whole script forever.

Exits 0 only if every test both builds and passes.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)

TIMEOUT_SECONDS = 15

# test_client and test_crypto are already covered by ctest via CMake;
# no need to duplicate them here.
SKIP = {"test_client", "test_crypto"}


def find_test_names():
    names = []
    for fname in sorted(os.listdir("src")):
        if fname.startswith("test_") and fname.endswith(".cpp"):
            name = fname[:-4]
            if name not in SKIP:
                names.append(name)
    return names


def parse_build_comment(path):
    with open(path) as f:
        content = f.read()
    m = re.search(r'// Build:\n((?://.*\n)+)', content)
    if not m:
        return None
    lines = []
    for line in m.group(1).split('\n'):
        line = re.sub(r'^//\s*', '', line)
        if not line.strip():
            break
        lines.append(line.rstrip('\\').strip())
    full = ' '.join(lines)
    tokens = full.split()
    sources = [t for t in tokens if t.endswith('.c') or t.endswith('.cpp')]
    libs = [t for t in tokens if t.startswith('-l')]
    return sources, libs


def build_and_run(name):
    path = f"src/{name}.cpp"
    parsed = parse_build_comment(path)
    if parsed is None:
        return "NO BUILD COMMENT", None
    sources, libs = parsed

    objects = []
    for src in sources:
        obj = f"/tmp/_std_{os.path.basename(src)}.o"
        compiler = "gcc -std=c11" if src.endswith('.c') else "g++ -std=c++17"
        cmd = f"{compiler} -Iinc -c {src} -o {obj}"
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if r.returncode != 0:
            return "COMPILE FAILED", f"{src}:\n{r.stderr[-800:]}"
        objects.append(obj)

    binpath = f"/tmp/_std_{name}"
    link_cmd = f"g++ {' '.join(objects)} {' '.join(libs)} -o {binpath}"
    r = subprocess.run(link_cmd, shell=True, capture_output=True, text=True)
    if r.returncode != 0:
        return "LINK FAILED", r.stderr[-800:]

    try:
        r = subprocess.run([binpath], capture_output=True, text=True,
                            timeout=TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return "TIMED OUT (possible hang/deadlock)", None
    finally:
        if os.path.exists(binpath):
            os.remove(binpath)

    if r.returncode != 0:
        return "RUNTIME FAILURE", (r.stdout + r.stderr)[-800:]

    return "OK", r.stdout.strip()


def main():
    names = find_test_names()
    failures = []
    for name in names:
        status, detail = build_and_run(name)
        mark = "PASS" if status == "OK" else "FAIL"
        print(f"[{mark}] {name}: {status}")
        if status != "OK":
            failures.append(name)
            if detail:
                print(f"       {detail}")

    print()
    print(f"{len(names) - len(failures)}/{len(names)} standalone tests passed")
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
