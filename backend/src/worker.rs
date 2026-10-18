//! 私有协议运行包与有界子进程管道

use crate::host::fault;
use gateway_plugin_sdk::PluginFault;
use serde_json::Value;
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::Stdio,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
};

#[derive(Default)]
pub struct Output {
    pub step: String,
    pub result: Option<Value>,
}
pub struct Worker {
    pub child: Child,
    pub output: Arc<Mutex<Output>>,
    pub started: u64,
    pub flow: String,
    pub snapshot: Value,
    pub request_id: String,
}
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}
pub struct Runtime {
    directory: Option<tempfile::TempDir>,
    ready: bool,
}
const RUNTIME_CHECK: &str = "from selfcheck import check_runtime; check_runtime()";

fn unpack_error(error: io::Error) -> PluginFault {
    fault(match error.kind() {
        io::ErrorKind::StorageFull => "协议运行目录空间不足，请检查插件数据盘",
        io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem => {
            "协议运行目录不可写，请检查插件数据目录权限"
        }
        _ => "协议运行包解包失败",
    })
}

fn unpack_runtime<R: Read>(archive: R, root: &Path) -> Result<tempfile::TempDir, PluginFault> {
    // 使用宿主已能执行插件的数据盘，不占用可能很小且禁止执行的系统临时盘
    let directory = tempfile::Builder::new()
        .prefix(".reauth-runtime-")
        .tempdir_in(root)
        .map_err(unpack_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(unpack_error)?;
    }
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut expanded = 0u64;
    for entry in tar.entries().map_err(|_| fault("协议运行包无效"))? {
        let mut entry = entry.map_err(|_| fault("协议运行包无效"))?;
        expanded = expanded.saturating_add(entry.size());
        if expanded > 256 * 1024 * 1024
            || !(entry.header().entry_type().is_file() || entry.header().entry_type().is_dir())
            || !entry.unpack_in(directory.path()).map_err(unpack_error)?
        {
            return Err(fault("协议运行包路径或大小无效"));
        }
    }
    Ok(directory)
}

#[cfg(debug_assertions)]
fn test_command() -> Option<Command> {
    let python = std::env::var("RS_REAUTH_TEST_PYTHON").ok()?;
    let script = std::env::var("RS_REAUTH_TEST_WORKER").ok()?;
    let mut command = Command::new(python);
    command.arg("-B").arg(script);
    Some(command)
}

impl Runtime {
    pub fn new() -> Self {
        Self {
            directory: None,
            ready: false,
        }
    }
    pub fn cleanup(&mut self) -> Result<(), PluginFault> {
        self.ready = false;
        if let Some(directory) = self.directory.take() {
            directory
                .close()
                .map_err(|_| fault("协议运行目录清理失败"))?;
        }
        Ok(())
    }
    fn python(&mut self) -> Result<Command, PluginFault> {
        if self.directory.is_none() {
            let root = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent()?.parent().map(PathBuf::from))
                .ok_or_else(|| fault("插件资源目录不可用"))?;
            let archive = std::fs::File::open(root.join("runtime/runtime.tar.gz"))
                .map_err(|_| fault("协议运行包缺失"))?;
            self.directory = Some(unpack_runtime(archive, &root)?);
        }
        let root = self
            .directory
            .as_ref()
            .ok_or_else(|| fault("运行环境未就绪"))?
            .path();
        let mut command = Command::new(root.join("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"));
        command
            .arg("--library-path")
            .arg(format!(
                "{}/usr/local/lib:{}/usr/lib/x86_64-linux-gnu",
                root.display(),
                root.display()
            ))
            .arg(root.join("usr/local/bin/python3.11"))
            .arg("-B");
        command
            .env_clear()
            .env("PYTHONHOME", root.join("usr/local"))
            .env("PYTHONPATH", root.join("protocol"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("TMPDIR", root)
            .env(
                "SSL_CERT_FILE",
                root.join("etc/ssl/certs/ca-certificates.crt"),
            )
            .env("HOME", root)
            .env("LANG", "C.UTF-8");
        Ok(command)
    }
    pub async fn prepare(&mut self) -> Result<(), PluginFault> {
        if self.ready {
            return Ok(());
        }
        #[cfg(debug_assertions)]
        if test_command().is_some() {
            self.ready = true;
            return Ok(());
        }
        let mut command = self.python()?;
        let mut child = command
            .arg("-c")
            .arg(RUNTIME_CHECK)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| fault("协议进程无法启动，请检查插件数据盘的执行权限"))?;
        let status =
            match tokio::time::timeout(std::time::Duration::from_secs(20), child.wait()).await {
                Ok(Ok(status)) => status,
                _ => {
                    let _ = child.kill().await;
                    return Err(fault("协议运行环境自检超时或进程异常"));
                }
            };
        if !status.success() {
            return Err(fault("协议依赖自检失败，尚未发起账号登录"));
        }
        self.ready = true;
        Ok(())
    }
    fn command(&mut self) -> Result<Command, PluginFault> {
        #[cfg(debug_assertions)]
        if let Some(command) = test_command() {
            return Ok(command);
        }
        let mut command = self.python()?;
        let root = self
            .directory
            .as_ref()
            .ok_or_else(|| fault("运行环境未就绪"))?
            .path();
        command.arg(root.join("protocol/runner.py"));
        Ok(command)
    }
    pub async fn start(
        &mut self,
        input: Value,
        flow: String,
        snapshot: Value,
        request_id: String,
    ) -> Result<Worker, PluginFault> {
        self.prepare().await?;
        let mut command = self.command()?;
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| fault("协议进程启动失败"))?;
        let stdout = child.stdout.take().ok_or_else(|| fault("协议通道不可用"))?;
        let mut stdin = child.stdin.take().ok_or_else(|| fault("协议通道不可用"))?;
        let bytes = serde_json::to_vec(&input).map_err(|_| fault("协议请求无效"))?;
        stdin
            .write_all(&bytes)
            .await
            .map_err(|_| fault("协议进程不可用"))?;
        stdin
            .shutdown()
            .await
            .map_err(|_| fault("协议进程不可用"))?;
        let output = Arc::new(Mutex::new(Output::default()));
        let target = Arc::clone(&output);
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout.take(131072));
            let mut line = String::new();
            loop {
                line.clear();
                if !matches!(reader.read_line(&mut line).await, Ok(n) if n > 0) {
                    break;
                }
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                let Ok(mut data) = target.lock() else {
                    break;
                };
                match value["event"].as_str() {
                    Some("step") => {
                        data.step = match value["step"].as_str() {
                            Some("session") => "session",
                            Some("session_restart") => "session_restart",
                            Some("login") => "login",
                            Some("mfa") => "mfa",
                            _ => "running",
                        }
                        .into();
                    }
                    Some(
                        "complete" | "free_fallback" | "forced_workspace" | "forced_free"
                        | "team_upgrade" | "error",
                    ) => {
                        data.result = Some(value);
                        break;
                    }
                    _ => break,
                }
            }
        });
        Ok(Worker {
            child,
            output,
            started: crate::host::now(),
            flow,
            snapshot,
            request_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};

    fn package(link: bool) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        if link {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_link_name("/outside").unwrap();
        } else {
            header.set_size(7);
        }
        header.set_cksum();
        tar.append_data(
            &mut header,
            "protocol/test.py",
            if link { &b""[..] } else { &b"fixture"[..] },
        )
        .unwrap();
        tar.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn runtime_uses_private_plugin_directory_and_cleans_it_up() {
        let package_root = tempfile::tempdir().unwrap();
        let runtime = unpack_runtime(package(false).as_slice(), package_root.path()).unwrap();
        let extracted = runtime.path().to_owned();
        assert_eq!(extracted.parent(), Some(package_root.path()));
        assert_eq!(
            std::fs::read(extracted.join("protocol/test.py")).unwrap(),
            b"fixture"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&extracted).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        drop(runtime);
        assert!(!extracted.exists());
    }
    #[test]
    fn invalid_and_link_archives_leave_no_partial_runtime() {
        let package_root = tempfile::tempdir().unwrap();
        assert!(unpack_runtime(package(true).as_slice(), package_root.path()).is_err());
        assert!(unpack_runtime(&b"invalid"[..], package_root.path()).is_err());
        assert_eq!(std::fs::read_dir(package_root.path()).unwrap().count(), 0);
    }
    #[test]
    fn explicit_cleanup_removes_runtime_even_if_manager_is_retained() {
        let package_root = tempfile::tempdir().unwrap();
        let directory = unpack_runtime(package(false).as_slice(), package_root.path()).unwrap();
        let extracted = directory.path().to_owned();
        let mut runtime = Runtime {
            directory: Some(directory),
            ready: true,
        };
        runtime.cleanup().unwrap();
        assert!(!extracted.exists());
        assert!(!runtime.ready);
        assert!(runtime.directory.is_none());
        runtime.cleanup().unwrap();
    }
    #[test]
    fn disk_and_permission_errors_are_actionable_without_private_paths() {
        assert!(
            unpack_error(io::Error::from(io::ErrorKind::StorageFull))
                .message
                .contains("空间不足")
        );
        assert!(
            unpack_error(io::Error::from(io::ErrorKind::PermissionDenied))
                .message
                .contains("不可写")
        );
    }
}
