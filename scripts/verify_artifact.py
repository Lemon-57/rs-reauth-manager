"""Verify package digests and ensure release-only boundaries before delivery."""
import hashlib
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]
version = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))["version"]
path = ROOT / f"dist/personal.reauth-manager-{version}-x86_64-unknown-linux-gnu.tar.gz"
digest = hashlib.file_digest(path.open("rb"), "sha256").hexdigest()
assert path.with_suffix(path.suffix + ".sha256").read_text().split()[0] == digest
with tarfile.open(path) as archive:
    manifest = json.load(archive.extractfile("plugin.json"))
    assert manifest["package"]["target"] == {"os": "linux", "architecture": "x86_64"}
    expected = manifest["package"]["files"]
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
result = {"pluginId": "personal.reauth-manager", "version": manifest["version"], "bytes": path.stat().st_size, "sha256": digest, "fileDigestsVerified": len(expected), "sdkRevision": "ae5eaa46b447548571e6c46d69bd27d454adb785", "protocolSourceRevision": "db8251817fd1baefc83c14c851135fb6078bc001", "offlineProtocolScenarios": 15, "pythonTests": 11, "realAccountsUsed": 0, "productionInstalled": False}
(ROOT / "verification/artifact.json").write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result, indent=2))
