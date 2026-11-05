"""Verify onboarding identities against the existing fixed-proxy ownership ledger."""
import hashlib
import re


class IdentityError(ValueError):
    pass


def reservation_confirmed(receipt, entry, row):
    reservation = entry.get('reservation_id')
    if not reservation:
        return False
    if receipt.get('requestId') == reservation:
        return True
    # Approved recovery retains the original fixed reservation in its history.
    if (receipt.get('recoveryApproved') is not True or receipt.get('exitVerified') is not True
            or receipt.get('phase') != 'bound' or receipt.get('nativeCompleteConfirmed') is not True):
        return False
    history = receipt.get('recoveryHistory')
    if not isinstance(history, list):
        return False
    return any(isinstance(old, dict)
               and old.get('requestId') == reservation
               and old.get('entryId') == row['management_id']
               and str(old.get('email') or '').casefold() == row['email'].casefold()
               and (old.get('phase') in {'native_complete_pending', 'native_started'}
                    and old.get('exitVerified') is True
                    or old.get('phase') == 'reserved' and not old.get('flowId')) for old in history)


def registered_mappings(rows, registry, receipt_for_email, validate_legacy, chat_identities=None):
    """Project verified proxy identities into stable Chat2API management IDs."""
    chat_identities = {} if chat_identities is None else chat_identities
    legacy = []
    onboarding = []
    for row in rows:
        mid = row.get('management_id', '')
        original = row.get('original_rs_id')
        if not isinstance(original, str) or not original:
            raise IdentityError('Missing registered source identity')
        expected = 'acct_' + hashlib.sha256(('rs:' + original).encode()).hexdigest()[:24]
        if mid == expected:
            legacy.append(row)
            continue
        target = row.get('target_rs_id')
        if (isinstance(target, str) and re.fullmatch(r'acct_[0-9a-f]{32}', target)
                and re.fullmatch(r'acct_[0-9a-f]{32}', original)
                and mid == 'acct_' + hashlib.sha256(('rs:' + target).encode()).hexdigest()[:24]):
            # A destination allocator creates its stable ID from the local RS ID.
            # Keep migration provenance separate from that identity seed.
            entry = registry.get(mid)
            if (not isinstance(entry, dict)
                    or entry.get('management_id') != mid
                    or entry.get('rs_account_id') != target
                    or not row.get('user_id')
                    or entry.get('user_id') != row['user_id']
                    or not isinstance(row.get('email'), str) or not row['email']
                    or str(entry.get('email') or '').casefold() != row['email'].casefold()
                    or row.get('migrated_from_rs_id') not in (None, original)):
                raise IdentityError('Destination fixed-proxy ownership mismatch')
            legacy.append(dict(row, original_rs_id=target, migrated_from_rs_id=original))
            continue
        if not isinstance(mid, str) or not re.fullmatch(r'onboarding_[0-9a-f]{32}', mid):
            raise IdentityError('Unknown registered identity format')
        if original != row.get('target_rs_id'):
            raise IdentityError('Onboarding source identity changed')
        entry = registry.get(mid)
        if not isinstance(entry, dict) or (
            entry.get('management_id') != mid
            or entry.get('rs_account_id') != original
            or not row.get('user_id')
            or entry.get('user_id') != row['user_id']
            or not isinstance(row.get('email'), str)
            or str(entry.get('email') or '').casefold() != row['email'].casefold()
        ):
            raise IdentityError('Onboarding fixed-proxy ownership mismatch')
        receipt = receipt_for_email(row['email'])
        if not isinstance(receipt, dict) or (
            receipt.get('phase') != 'bound'
            or receipt.get('nativeCompleteConfirmed') is not True
            or receipt.get('entryId') != mid
            or receipt.get('accountId') != original
            or str(receipt.get('email') or '').casefold() != row['email'].casefold()
            or not reservation_confirmed(receipt, entry, row)
        ):
            raise IdentityError('Onboarding native binding receipt unconfirmed')
        destination = chat_identities.get(mid, expected)
        if not isinstance(destination, str) or not re.fullmatch(r'acct_[0-9a-f]{24}', destination):
            raise IdentityError('Invalid destination identity binding')
        onboarding.append(dict(row, management_id=destination))

    result = dict(validate_legacy(legacy))
    seen = {key: set() for key in ('original_rs_id', 'target_rs_id', 'management_id')}
    principals = set()
    for row in legacy + onboarding:
        for key, values in seen.items():
            value = row.get(key)
            if not isinstance(value, str) or not value or value in values:
                raise IdentityError('Duplicate registered identity')
            values.add(value)
        if not isinstance(row.get('email'), str) or not row['email'] or not row.get('user_id'):
            raise IdentityError('Incomplete registered principal')
        principal = (row['email'].casefold(), row['user_id'], row.get('workspace_id'))
        if principal in principals:
            raise IdentityError('Duplicate registered principal')
        principals.add(principal)
        result[row['target_rs_id']] = row
    return result
