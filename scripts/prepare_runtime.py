"""Download pinned public runtime inputs locally without a Docker daemon."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "index.docker.io/library/python@sha256:8a00ecb83ed9d0864dfd102a1bdb2067fda907ceb30bb86d09da9ee558b19590"
CONFIG = "sha256:141fe9b385f3bb6d618c07ace1836c0b3c72bf525566ac3eb13cd1f405069877"
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cache-dir", type=Path, default=ROOT / ".cache/runtime")
parser.add_argument("--crane", default=shutil.which("crane"))
args = parser.parse_args()
cache = args.cache_dir.resolve()
cache.mkdir(parents=True, exist_ok=True)
base = cache / "python-base.tar"
if not base.exists():
    if not args.crane:
        parser.error("Install crane v0.20.6 or pass --crane /path/to/crane")
    subprocess.run([args.crane, "pull", "--platform", "linux/amd64", IMAGE, str(base)], check=True)
with tarfile.open(base) as image:
    manifest = json.load(image.extractfile("manifest.json"))[0]
    config = image.extractfile(manifest["Config"]).read()
    if "sha256:" + hashlib.sha256(config).hexdigest() != CONFIG:
        raise RuntimeError("Runtime base does not match the pinned configuration")
    metadata = json.loads(config)
    if metadata["os"] != "linux" or metadata["architecture"] != "amd64":
        raise RuntimeError("Runtime base must be Linux x86_64")
wheels = cache / "wheels"
wheels.mkdir(exist_ok=True)
subprocess.run([
    sys.executable, "-m", "pip", "download", "--dest", str(wheels),
    "--only-binary=:all:", "--require-hashes", "--platform", "manylinux2014_x86_64",
    "--platform", "manylinux_2_17_x86_64", "--platform", "manylinux_2_28_x86_64",
    "--python-version", "3.11", "--implementation", "cp", "--abi", "cp311", "--abi", "abi3",
    "--requirement", str(ROOT / "protocol/requirements-linux.txt"),
], check=True)
dependencies = cache / "linux-deps"
dependencies.mkdir(exist_ok=True)
digests = {}
for wheel in sorted(wheels.glob("*.whl")):
    digests[wheel.name] = hashlib.file_digest(wheel.open("rb"), "sha256").hexdigest()
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            if path.is_absolute() or ".." in path.parts:
                raise RuntimeError("Unsafe wheel member")
        archive.extractall(dependencies)
(cache / "wheels.sha256.json").write_text(json.dumps(digests, indent=2) + "\n")
print(json.dumps({"baseConfiguration": CONFIG, "wheelCount": len(digests), "cache": str(cache)}))
