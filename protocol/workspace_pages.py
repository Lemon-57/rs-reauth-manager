"""Read bounded workspace evidence from JSON hydration data, never execute page scripts."""
import json
import re
from html.parser import HTMLParser

_ID = re.compile(r'[A-Za-z0-9_-]{1,128}')
_UUID = re.compile(r'[0-9a-fA-F-]{36}')
_FIELDS = ('type', 'account_type', 'kind', 'plan_type', 'is_personal')


class _Scripts(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.parts, self.current = [], None

    def handle_starttag(self, tag, attrs):
        if tag == 'script':
            self.current = []

    def handle_data(self, data):
        if self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.current is not None:
            self.parts.append(''.join(self.current))
            self.current = None


def _script_json_values(source, decoder):
    """Scan JSON entry points without interpreting JS strings, comments or expressions."""
    position, accepted, attempts = 0, 0, 0
    length = len(source)
    call = re.compile(r'(?:enqueue|JSON\s*\.\s*parse)\s*\(\s*')
    while position < length:
        char = source[position]
        if char in {'"', "'", '`'}:
            quote = char
            position += 1
            while position < length:
                if source[position] == '\\':
                    position += 2
                elif source[position] == quote:
                    position += 1
                    break
                else:
                    position += 1
            continue
        if source.startswith('//', position):
            end = source.find('\n', position + 2)
            position = length if end < 0 else end + 1
            continue
        if source.startswith('/*', position):
            end = source.find('*/', position + 2)
            position = length if end < 0 else end + 2
            continue
        if char == '/':
            prefix = source[max(0, position - 64):position].rstrip()
            regex_start = not prefix or prefix[-1] in '=(:,;![{?&|+*%~' or re.search(r'\b(?:return|throw|case|typeof|void|delete|yield|await)$', prefix)
            if regex_start:
                end, in_class = position + 1, False
                while end < length and source[end] not in '\r\n':
                    if source[end] == '\\':
                        end += 2
                        continue
                    if source[end] == '[':
                        in_class = True
                    elif source[end] == ']':
                        in_class = False
                    elif source[end] == '/' and not in_class:
                        end += 1
                        while end < length and source[end].isalpha():
                            end += 1
                        position = end
                        break
                    end += 1
                else:
                    position += 1
                continue
        match = call.match(source, position) if position == 0 or not (source[position - 1].isalnum() or source[position - 1] in {'_', '$'}) else None
        start = match.end() if match else None
        if char == '=' and (position == 0 or source[position - 1] not in '=!<>+-*/%&|^?') and (position + 1 == length or source[position + 1] not in '=>'):
            start = position + 1
            while start < length and source[start].isspace():
                start += 1
        if start is not None and start < length and source[start] in '{["':
            attempts += 1
            if attempts > 512:
                raise ValueError('workspace_evidence_invalid')
            try:
                value, end = decoder.raw_decode(source, start)
            except (ValueError, RecursionError):
                pass
            else:
                if isinstance(value, (dict, list)) or (isinstance(value, str) and value.lstrip().startswith(('{', '['))):
                    accepted += 1
                    if accepted > 64:
                        raise ValueError('workspace_evidence_invalid')
                    yield value
                position = end
                continue
        position += 1


def workspace_page(text):
    text = str(text or '')
    if len(text) > 2 * 1024 * 1024:
        raise ValueError('workspace_evidence_invalid')
    parser = _Scripts()
    parser.feed(text)
    decoder = json.JSONDecoder()
    candidates, documents, visited = {}, [], 0

    def add(wid, fields=None):
        if not isinstance(wid, str) or not _ID.fullmatch(wid):
            raise ValueError('workspace_evidence_invalid')
        if wid not in candidates:
            if len(candidates) >= 30:
                raise ValueError('workspace_evidence_invalid')
            candidates[wid] = {'id': wid}
        for key, value in (fields or {}).items():
            if key not in _FIELDS:
                continue
            if value is None or value == '':
                continue
            if (key == 'is_personal' and type(value) is not bool) or (key != 'is_personal' and not isinstance(value, str)):
                raise ValueError('workspace_evidence_invalid')
            if key in candidates[wid] and candidates[wid][key] != value:
                raise ValueError('workspace_evidence_invalid')
            candidates[wid][key] = value

    def walk(value, depth=0, decode_string=False):
        nonlocal visited
        visited += 1
        if visited > 12000 or depth > 20:
            raise ValueError('workspace_evidence_invalid')
        if isinstance(value, str) and decode_string:
            stripped = value.lstrip()
            if stripped.startswith(('{', '[', '"')):
                try:
                    nested = json.loads(stripped)
                except (ValueError, RecursionError):
                    return
                walk(nested, depth + 1, decode_string=True)
        elif isinstance(value, dict):
            for key, child in value.items():
                if key in {'workspace_id', 'workspaceId'}:
                    if child is not None and child != '':
                        add(child)
                elif key == 'workspaces':
                    if not isinstance(child, list) or any(not isinstance(w, dict) for w in child):
                        raise ValueError('workspace_evidence_invalid')
                    ids = [w.get('id') for w in child]
                    if any(not isinstance(wid, str) for wid in ids) or len(set(ids)) != len(ids):
                        raise ValueError('workspace_evidence_invalid')
                    for workspace in child:
                        add(workspace['id'], workspace)
                else:
                    walk(child, depth + 1)
        elif isinstance(value, list):
            if referenced_workspaces(value):
                return
            # Upstream also accepts the flattened React Router hydration representation.
            flattened_workspaces = any(item == 'workspaces' for item in value if isinstance(item, str))
            for index, child in enumerate(value):
                if isinstance(child, str) and index + 1 < len(value):
                    following = value[index + 1]
                    if child in {'workspace_id', 'workspaceId'}:
                        add(following)
                    elif flattened_workspaces and child == 'id' and isinstance(following, str) and _UUID.fullmatch(following):
                        add(following)
                walk(child, depth + 1)

    def referenced_workspaces(table):
        if len(table) > 12000:
            raise ValueError('workspace_evidence_invalid')
        entries = []
        for value in table:
            if not isinstance(value, dict):
                continue
            for key, reference in value.items():
                if not re.fullmatch(r'_[0-9]+', key):
                    continue
                index = int(key[1:])
                if index >= len(table):
                    raise ValueError('workspace_evidence_invalid')
                field = table[index]
                if isinstance(field, str) and field in {'workspaces', 'workspace_id', 'workspaceId'}:
                    entries.append((field, reference))
        if not entries:
            return False
        active, cache = set(), {}

        def resolve(index, depth=0):
            nonlocal visited
            visited += 1
            if visited > 12000 or depth > 20 or type(index) is not int or not 0 <= index < len(table) or index in active:
                raise ValueError('workspace_evidence_invalid')
            if index in cache:
                return cache[index]
            active.add(index)
            value = table[index]
            if isinstance(value, dict):
                resolved = {}
                for key, reference in value.items():
                    if not re.fullmatch(r'_[0-9]+', key):
                        raise ValueError('workspace_evidence_invalid')
                    field = resolve(int(key[1:]), depth + 1)
                    if not isinstance(field, str) or field in resolved:
                        raise ValueError('workspace_evidence_invalid')
                    if field not in {'id', *_FIELDS}:
                        continue
                    if field in _FIELDS and type(reference) is int and reference < 0:
                        continue
                    resolved[field] = resolve(reference, depth + 1)
            elif isinstance(value, list):
                resolved = [resolve(reference, depth + 1) for reference in value]
            else:
                resolved = value
            active.remove(index)
            cache[index] = resolved
            return resolved

        for field, reference in entries:
            walk({field: resolve(reference)})
        return True

    for source in parser.parts or [text]:
        source = source.strip()
        try:
            value = json.loads(source)
        except (ValueError, RecursionError):
            documents.extend(_script_json_values(source, decoder))
        else:
            documents.append(value)
    for value in documents:
        walk(value, decode_string=True)
    return {'workspaces': list(candidates.values())}
