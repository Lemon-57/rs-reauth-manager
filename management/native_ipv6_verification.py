"""通过已登记固定认证检查独立 IPv6，绝不分配地址或执行授权"""
import base64
import http.client
import ipaddress
import ssl
import time


class ExitVerificationError(Exception):
    pass


def verify_native_exit(entry, connection_factory=http.client.HTTPSConnection,
                       clock=time.monotonic, sleep=time.sleep):
    expected = ipaddress.IPv6Address(entry['ipv6'])
    auth = 'Basic ' + base64.b64encode((entry['username'] + ':' + entry['password']).encode()).decode()
    deadline = clock() + 18
    context = ssl.create_default_context()
    probes = [('api6.ipify.org', '/', False), ('www.cloudflare.com', '/cdn-cgi/trace', True)] * 2
    for index, (host, path, trace) in enumerate(probes):
        remaining = deadline - clock()
        if remaining <= 0:
            break
        connection = connection_factory(entry['host'], entry['port'], timeout=min(4, remaining), context=context)
        try:
            connection.set_tunnel(host, 443, headers={'Proxy-Authorization': auth})
            connection.request('GET', path, headers={'Host': host, 'Connection': 'close'})
            response = connection.getresponse()
            if response.status != 200:
                continue
            raw = response.read(4097)
            if len(raw) > 4096:
                raise ExitVerificationError('exit_response_invalid')
            text = raw.decode('ascii').strip()
            address = next((line[3:] for line in text.splitlines() if line.startswith('ip=')), '') if trace else text
            try:
                actual = ipaddress.IPv6Address(address)
            except ValueError:
                raise ExitVerificationError('exit_address_invalid') from None
            if actual != expected:
                raise ExitVerificationError('exit_address_mismatch')
            return
        except (OSError, http.client.HTTPException):
            # 只重试检测站读取，认证、代理端点和预留归属保持原值
            if index < len(probes) - 1 and deadline - clock() > .2:
                sleep(.2)
        except UnicodeDecodeError:
            raise ExitVerificationError('exit_response_invalid') from None
        finally:
            connection.close()
    raise ExitVerificationError('exit_unavailable')
