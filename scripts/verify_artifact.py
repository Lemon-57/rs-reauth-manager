"""Verify package digests and ensure release-only boundaries before delivery."""
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tomllib
from page_resources import validate_page_resources

ROOT = Path(__file__).resolve().parents[1]
version = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))["version"]
sdk_revision = tomllib.loads((ROOT / "backend/Cargo.toml").read_text(encoding="utf-8"))["dependencies"]["gateway-plugin-sdk"]["rev"]
path = ROOT / f"dist/personal.reauth-manager-{version}-x86_64-unknown-linux-gnu.tar.gz"
digest = hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
assert path.with_suffix(path.suffix + ".sha256").read_text().split()[0] == digest
with tarfile.open(path) as archive:
    manifest = json.load(archive.extractfile("plugin.json"))
    assert manifest["version"] == version, "Package version differs from source manifest"
    assert manifest["manifestVersion"] == 2
    assert manifest["package"]["protocolVersion"] == 5
    assert manifest["contributes"]["management"]["version"] == 2
    assert manifest["contributes"]["maintenance"]["version"] == 1
    assert manifest["engines"] == {"codex-proxy-rs": ">=3.29.7, <3.30.0"}
    assert manifest["package"]["target"] == {"os": "linux", "architecture": "x86_64"}
    expected = manifest["package"]["files"]
    validate_page_resources(archive.extractfile("web/index.html").read().decode("utf-8"), manifest["resources"])
    assert set(archive.getnames()) == {"plugin.json", *expected}
    for name, expected_digest in expected.items():
        raw = archive.extractfile(name).read()
        assert hashlib.sha256(raw).hexdigest() == expected_digest
        if name == "bin/reauth-manager":
            assert raw.startswith(b"\x7fELF")
            for marker in [b"RS_REAUTH_TEST_WORKER", b"RS_REAUTH_TEST_PYTHON", b"fixture-password"]:
                assert marker not in raw
        if name == "web/app.js":
            assert b"acct_preview_" not in raw and b"fixture-password" not in raw
    with tarfile.open(fileobj=io.BytesIO(archive.extractfile("runtime/runtime.tar.gz").read())) as runtime:
        assert "protocol/sessions.py" not in runtime.getnames(), "Removed device module must not be packaged"
        for source in (ROOT / "protocol").rglob("*"):
            if source.is_file() and "__pycache__" not in source.parts and source.suffix != ".pyc":
                raw = source.read_bytes()
                if source.suffix in {".py", ".txt"} or source.name.startswith("LICENSE"):
                    raw = raw.replace(b"\r\n", b"\n")
                assert runtime.extractfile("protocol/" + source.relative_to(ROOT / "protocol").as_posix()).read() == raw, "Packaged protocol differs from source"
result = {"pluginId": "personal.reauth-manager", "version": manifest["version"], "bytes": path.stat().st_size, "sha256": digest, "protocolVersion": manifest["package"]["protocolVersion"], "fileDigestsVerified": len(expected), "sdkRevision": sdk_revision, "protocolSourceRevision": "db8251817fd1baefc83c14c851135fb6078bc001"}
(ROOT / "verification/artifact.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
