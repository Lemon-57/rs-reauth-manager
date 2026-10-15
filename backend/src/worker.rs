//! 私有协议运行包与有界子进程管道

use crate::host::fault;
use gateway_plugin_sdk::PluginFault;
use serde_json::Value;
use std::{
    path::PathBuf,
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
}
impl Runtime {
    pub fn new() -> Self {
        Self { directory: None }
    }
    fn command(&mut self) -> Result<Command, PluginFault> {
        #[cfg(debug_assertions)]
        if let (Ok(python), Ok(script)) = (
            std::env::var("RS_REAUTH_TEST_PYTHON"),
            std::env::var("RS_REAUTH_TEST_WORKER"),
        ) {
            let mut command = Command::new(python);
            command.arg("-B").arg(script);
            return Ok(command);
        }
        if self.directory.is_none() {
            let root = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent()?.parent().map(PathBuf::from))
                .ok_or_else(|| fault("插件资源目录不可用"))?;
            let archive = std::fs::File::open(root.join("runtime/runtime.tar.gz"))
                .map_err(|_| fault("协议运行包缺失"))?;
            let directory = tempfile::Builder::new()
                .prefix("rs-reauth-")
                .tempdir()
                .map_err(|_| fault("无法创建隔离运行目录"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                    .map_err(|_| fault("运行目录权限设置失败"))?;
            }
            let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
            let mut expanded = 0u64;
            for entry in tar.entries().map_err(|_| fault("协议运行包无效"))? {
                let mut entry = entry.map_err(|_| fault("协议运行包无效"))?;
                expanded = expanded.saturating_add(entry.size());
                if expanded > 256 * 1024 * 1024
                    || !(entry.header().entry_type().is_file()
                        || entry.header().entry_type().is_dir())
                    || !entry
                        .unpack_in(directory.path())
                        .map_err(|_| fault("协议运行包解包失败"))?
                {
                    return Err(fault("协议运行包路径或大小无效"));
                }
            }
            self.directory = Some(directory);
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
            .arg("-B")
            .arg(root.join("protocol/runner.py"));
        command
            .env_clear()
            .env("PYTHONHOME", root.join("usr/local"))
            .env("PYTHONPATH", root.join("protocol"))
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env(
                "SSL_CERT_FILE",
                root.join("etc/ssl/certs/ca-certificates.crt"),
            )
            .env("HOME", root)
            .env("LANG", "C.UTF-8");
        Ok(command)
    }
    pub async fn start(
        &mut self,
        input: Value,
        flow: String,
        snapshot: Value,
        request_id: String,
    ) -> Result<Worker, PluginFault> {
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
            let mut reader = BufReader::new(stdout.take(32768));
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
                            Some("login") => "login",
                            Some("mfa") => "mfa",
                            _ => "running",
                        }
                        .into();
                    }
                    Some("complete" | "error") => {
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
