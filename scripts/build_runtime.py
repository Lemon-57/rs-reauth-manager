"""Build a private, self-contained Linux protocol runtime on the local machine."""
import gzip
import hashlib
import io
import json
import posixpath
import tarfile
import argparse
from pathlib import Path
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cache-dir", type=Path, default=ROOT / ".cache/runtime")
parser.add_argument("--base-tar", type=Path)
parser.add_argument("--dependencies-dir", type=Path)
args = parser.parse_args()
base_tar = args.base_tar or args.cache_dir / "python-base.tar"
dependencies = args.dependencies_dir or args.cache_dir / "linux-deps"
if not base_tar.is_file() or not dependencies.is_dir():
    parser.error("Run scripts/prepare_runtime.py first, or provide --base-tar and --dependencies-dir")
files = {}
with tarfile.open(base_tar) as image:
    manifest = json.load(image.extractfile("manifest.json"))[0]
    config = json.load(image.extractfile(manifest["Config"]))
    assert config["os"] == "linux" and config["architecture"] == "amd64"
    for name, digest in zip(manifest["Layers"], config["rootfs"]["diff_ids"], strict=True):
        data = image.extractfile(name).read()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        assert "sha256:" + hashlib.sha256(data).hexdigest() == digest
        with tarfile.open(fileobj=io.BytesIO(data)) as layer:
            for item in layer:
                path = item.name.removeprefix("./").rstrip("/")
                if "/.wh." in path:
                    target = path.replace("/.wh.", "/")
                    files.pop(target, None)
                    continue
                wanted = path.startswith(("usr/local/bin/python", "usr/local/lib/", "usr/lib/x86_64-linux-gnu/", "lib/x86_64-linux-gnu/", "lib64/", "etc/ssl/certs/", "usr/share/doc/"))
                if not wanted or item.isdir():
                    continue
                if item.issym():
                    dest = item.linkname if item.linkname.startswith("/") else posixpath.join(posixpath.dirname(path), item.linkname)
                    files[path] = ("link", posixpath.normpath(dest).lstrip("/"), item.mode)
                elif item.islnk():
                    files[path] = ("link", item.linkname.lstrip("/"), item.mode)
                elif item.isfile():
                    files[path] = ("file", layer.extractfile(item).read(), item.mode)


def resolve(path, seen=None):
    seen = set() if seen is None else seen
    if path not in files and path.startswith("lib/"):
        path = "usr/" + path
    if path in seen or path not in files:
        raise ValueError("Unresolved base runtime link: " + path)
    seen.add(path)
    kind, content, mode = files[path]
    return resolve(content, seen) if kind == "link" else (content, mode)


output = {}
for path in files:
    if path.startswith("usr/local/bin/") and path != "usr/local/bin/python3.11":
        continue
    if path.startswith("etc/ssl/certs/") and path != "etc/ssl/certs/ca-certificates.crt":
        continue
    if any(p in {"__pycache__", "test", "tests", "ensurepip", "idlelib", "tkinter", "turtledemo", "site-packages", "pkgconfig"} for p in path.split("/")) or path.endswith((".a", ".pyc")):
        continue
    if "/lib-dynload/" in path and path.rsplit("/", 1)[-1].startswith(("_tkinter", "_test", "_xx", "_ctypes_test")):
        continue
    if path.startswith("usr/share/doc/") and not path.endswith("/copyright"):
        continue
    if path.startswith(("usr/local/lib/", "etc/ssl/", "usr/share/doc/", "usr/local/bin/")):
        try:
            content, mode = resolve(path)
        except ValueError:
            if path.startswith("usr/share/doc/"):
                continue
            raise
        output[path] = (content, mode)

# The loader is invoked explicitly, so the gateway container need not supply Python or matching glibc.
loader = "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
if loader not in output:
    output[loader] = resolve(next(p for p in files if p.endswith("/ld-linux-x86-64.so.2")))
# Keep a single SONAME copy of libpython, instead of duplicating its symlink target.
output.pop("usr/local/lib/libpython3.11.so", None)
packages = {"curl_cffi", "cffi", "requests", "urllib3", "certifi", "idna", "charset_normalizer", "pycparser", "rich", "pygments", "markdown_it", "markdown_it_py", "mdurl"}
for path in sorted(dependencies.rglob("*")):
    if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
        continue
    relative = path.relative_to(dependencies)
    first = relative.parts[0]
    if first not in packages and not first.startswith("_cffi_backend") and not any(first.startswith(p + "-") for p in packages):
        continue
    raw = path.read_bytes()
    if ".so" in path.name:
        assert raw.startswith(b"\x7fELF"), "Non-Linux dependency"
    output["usr/local/lib/python3.11/site-packages/" + relative.as_posix()] = (raw, 0o755 if ".so" in path.name else 0o644)
for path in sorted((ROOT / "protocol").rglob("*")):
    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
        raw = path.read_bytes()
        if path.suffix in {".py", ".txt"} or path.name.startswith("LICENSE"):
            raw = raw.replace(b"\r\n", b"\n")
        output["protocol/" + path.relative_to(ROOT / "protocol").as_posix()] = (raw, 0o644)

# Resolve the real ELF dependency closure rather than shipping unrelated system libraries.
pending = list(output.values())
seen = set()
while pending:
    content, mode = pending.pop()
    if not content.startswith(b"\x7fELF"):
        continue
    elf = ELFFile(io.BytesIO(content))
    dynamic = elf.get_section_by_name(".dynamic")
    if dynamic is None:
        continue
    for tag in dynamic.iter_tags():
        if tag.entry.d_tag != "DT_NEEDED" or tag.needed in seen:
            continue
        soname = tag.needed
        seen.add(soname)
        if any(path.endswith("/" + soname) for path in output):
            continue
        candidates = ["usr/lib/x86_64-linux-gnu/" + soname, "lib/x86_64-linux-gnu/" + soname, "usr/local/lib/" + soname]
        source = next((p for p in candidates if p in files), None)
        assert source, "Missing ELF dependency: " + soname
        raw, mode = resolve(source)
        output["usr/lib/x86_64-linux-gnu/" + soname] = (raw, mode)
        pending.append((raw, mode))

destination = ROOT / "runtime" / "runtime.tar.gz"
destination.parent.mkdir(exist_ok=True)
with destination.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, compresslevel=9) as compressed, tarfile.open(fileobj=compressed, mode="w|", format=tarfile.PAX_FORMAT) as archive:
    for path, (content, mode) in sorted(output.items()):
        info = tarfile.TarInfo(path)
        info.size = len(content)
        info.mode = mode
        archive.addfile(info, io.BytesIO(content))
size = destination.stat().st_size
assert size < 29 * 1024 * 1024, "Runtime leaves insufficient room in RS's 32 MiB plugin package limit"
print(json.dumps({"files": len(output), "expandedBytes": sum(len(raw) for raw, mode in output.values()), "compressedBytes": size, "sha256": hashlib.file_digest(destination.open("rb"), "sha256").hexdigest()}, indent=2))
