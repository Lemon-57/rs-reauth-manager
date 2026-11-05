"""Add exact native-start receipt recovery to an existing fixed-pool adapter.

Load the verified active adapter, retaining its instance-specific allocation,
identity mapping, authentication, import, completion and ownership behavior.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


def recovery_adapter(base):
    class Adapter(base.Adapter):
        def start(self, headers, body):
            if not isinstance(body, dict) or set(body) != {'email', 'requestId'}:
                raise base.Rejected(422)
            email, request_id = body['email'], body['requestId']
            if not isinstance(email, str) or not isinstance(request_id, str):
                raise base.Rejected(422)
            path = self.receipt_path(email)
            if path.exists():
                receipt = json.loads(path.read_text())
                result = receipt.get('nativeStartResult')
                if receipt.get('requestId') == request_id and result is not None:
                    rows = self.directory(headers)
                    if (receipt.get('phase') != 'native_started'
                            or receipt.get('email', '').casefold() != email.casefold()
                            or any(row.get('provider') == 'openai' and
                                   str(row.get('email') or '').casefold() == email.casefold() for row in rows)
                            or not isinstance(result, dict)
                            or result.get('flowId') != receipt.get('flowId')):
                        raise base.Rejected(409)
                    try:
                        expiry = datetime.datetime.fromisoformat(result['expiresAt'].replace('Z', '+00:00'))
                        if expiry.timestamp() <= datetime.datetime.now(datetime.timezone.utc).timestamp() + 30:
                            raise ValueError('expired')
                    except (ValueError, KeyError, TypeError, AttributeError):
                        raise base.Rejected(409) from None
                    entries = [entry for entry in self.manager.rows()
                               if entry.get('management_id') == receipt.get('entryId')]
                    if (len(entries) != 1 or entries[0].get('rs_account_id')
                            or entries[0].get('email', '').casefold() != email.casefold()
                            or self.url(entries[0]) != result.get('outboundProxyUrl')):
                        raise base.Rejected(409)
                    self.verify_exit(entries[0])
                    return result
            result = super().start(headers, body)
            receipt = json.loads(path.read_text())
            if (receipt.get('requestId') != request_id or receipt.get('phase') != 'native_started'
                    or receipt.get('flowId') != result.get('flowId')):
                raise base.Rejected(409)
            receipt['nativeStartResult'] = result
            base.atomic(path, receipt)
            return result
    return Adapter


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--base-source', required=True)
    parser.add_argument('--base-sha256', required=True)
    args, remaining = parser.parse_known_args()
    path = Path(args.base_source).resolve(strict=True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != args.base_sha256:
        raise RuntimeError('active_adapter_source_changed')
    spec = importlib.util.spec_from_file_location('fixed_pool_base', path)
    base = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(base)
    base.Adapter = recovery_adapter(base)
    sys.argv = [str(path), *remaining]
    base.main()


if __name__ == '__main__':
    main()
