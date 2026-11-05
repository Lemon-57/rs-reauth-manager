"""从有效服务加载受保护原生导入实现，保留现行分配器和回执"""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys

from native_task_finalization import install


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--service-source', required=True)
    parser.add_argument('--service-sha256', required=True)
    args, remaining = parser.parse_known_args()
    path = Path(args.service_source).resolve(strict=True)
    if hashlib.sha256(path.read_bytes()).hexdigest() != args.service_sha256:
        raise RuntimeError('effective_service_changed')
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location('effective_native_import', path)
    service = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(service)
    install(service)
    source_sha = hashlib.sha256(Path(__file__).with_name('native_task_finalization.py').read_bytes()).hexdigest()
    OriginalHandler = service.Handler

    class Handler(OriginalHandler):
        def dispatch(self):
            if self.path == '/healthz' and self.command == 'GET':
                self.reply(200, {'status': 'ok', 'nativeTaskIndexBase': 1,
                    'sourceSha256': source_sha, 'automaticProPlans': ['pro', 'prolite']})
                return
            return super().dispatch()

        do_GET = dispatch
        do_POST = dispatch
        do_PUT = dispatch
        do_DELETE = dispatch

    service.Handler = Handler
    # 不恢复代理运行时，不创建/重载代理进程
    if '--no-recover' not in remaining:
        remaining.append('--no-recover')
    sys.argv = [str(path), *remaining]
    service.main()


if __name__ == '__main__':
    main()
