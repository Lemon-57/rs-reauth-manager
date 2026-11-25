# Reauthorization display fix 0.1.109

This patch targets the frontend used by reauthorization plugin `0.1.108` on RS `3.54.5`. It is stored separately because this repository branch does not contain the `0.1.108` baseline. This branch is not a full `0.1.109` source tree or an installation package.

When the account is currently unhealthy, desktop and mobile rows show its current status (including disabled status) ahead of a past successful writeback. The previous result and completion time remain visible as history. The patch contains two frontend changes and a regression test; no backend code, scheduling, or runtime is changed.

Run `git -c core.autocrlf=false apply --check --directory=frontend <path-to-frontend.patch>` from the matching plugin source root, then apply with the same arguments without `--check`. Do not apply this patch to an older baseline that fails the check. The patch keeps the original source line endings.

Frontend patch SHA-256: `375a22cc4c5a8b22c073d9a1cd8159d2ffea9644d616e66c67da3cc6eb07014d`.
