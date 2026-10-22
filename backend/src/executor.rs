//! 基于共享状态的独占执行租约，待命宿主只读，不恢复或推进任务
use crate::host::{fault, now};
use gateway_plugin_sdk::{
    ErrorCode, PluginFault,
    call::host::{StateGetResult, StatePutResult},
    client::HostClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const TTL: u64 = 120_000;
const RENEW: u64 = 10_000;
tokio::task_local! { static CURRENT: Arc<Executor>; }

#[derive(Serialize, Deserialize)]
struct Lease {
    owner: String,
    expires: u64,
}

pub struct Executor {
    owner: String,
    standby: AtomicBool,
}
impl Executor {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            owner: uuid::Uuid::new_v4().to_string(),
            standby: AtomicBool::new(false),
        })
    }
    async fn read(host: &HostClient) -> Result<(Option<Lease>, Option<u64>), PluginFault> {
        let reply = host
            .call(
                "host.state.get",
                json!({"namespace":"reauth-manager","key":"executor"}),
                vec![],
            )
            .await
            .map_err(|e| e.into_plugin_fault())?;
        let data: StateGetResult =
            serde_json::from_value(reply.result).map_err(|_| fault("执行权状态无效"))?;
        match data.record {
            Some(r) => Ok((
                Some(serde_json::from_value(r.value).map_err(|_| fault("执行权记录无效"))?),
                Some(r.version),
            )),
            None => Ok((None, None)),
        }
    }
    async fn put(
        host: &HostClient,
        lease: &Lease,
        version: Option<u64>,
    ) -> Result<(), PluginFault> {
        let reply = host.call("host.state.put", json!({"namespace":"reauth-manager","key":"executor","value":lease,"expected_version":version}), vec![]).await.map_err(|e| e.into_plugin_fault())?;
        let _: StatePutResult =
            serde_json::from_value(reply.result).map_err(|_| fault("执行权保存未确认"))?;
        Ok(())
    }
    async fn acquire(&self, host: &HostClient) -> Result<bool, PluginFault> {
        if self.standby.load(Ordering::SeqCst) {
            return Ok(false);
        }
        // 只重试执行权记录的版本竞争，不重放账号修改或 OAuth 请求
        for _ in 0..3 {
            let (lease, version) = Self::read(host).await?;
            let time = now();
            if lease
                .as_ref()
                .is_some_and(|l| l.owner != self.owner && l.expires > time)
            {
                return Ok(false);
            }
            if Self::put(
                host,
                &Lease {
                    owner: self.owner.clone(),
                    expires: time + TTL,
                },
                version,
            )
            .await
            .is_ok()
            {
                return Ok(true);
            }
        }
        Err(PluginFault::new(
            ErrorCode::Conflict,
            "执行权竞争未确认，请读取最新状态，未重复执行授权",
        ))
    }
    async fn renew(&self, host: &HostClient) -> Result<(), PluginFault> {
        let (lease, version) = Self::read(host).await?;
        if !lease.is_some_and(|l| l.owner == self.owner && l.expires > now()) {
            return Err(PluginFault::new(
                ErrorCode::Conflict,
                "后台执行权已变化，任务需核对，未自动重放",
            ));
        }
        Self::put(
            host,
            &Lease {
                owner: self.owner.clone(),
                expires: now() + TTL,
            },
            version,
        )
        .await
    }
    async fn check(&self, host: &HostClient) -> Result<(), PluginFault> {
        let (lease, _) = Self::read(host).await?;
        if self.standby.load(Ordering::SeqCst)
            || !lease.is_some_and(|l| l.owner == self.owner && l.expires > now())
        {
            return Err(PluginFault::new(
                ErrorCode::Conflict,
                "后台执行权已变化，任务需核对，未自动重放",
            ));
        }
        Ok(())
    }
    pub async fn run<T, F: Future<Output = Result<T, PluginFault>>>(
        self: &Arc<Self>,
        host: &HostClient,
        action: F,
    ) -> Result<Option<T>, PluginFault> {
        if !self.acquire(host).await? {
            return Ok(None);
        }
        CURRENT.scope(Arc::clone(self), async {
            tokio::pin!(action);
            loop {
                tokio::select! {
                    result = &mut action => return result.map(Some),
                    () = tokio::time::sleep(std::time::Duration::from_millis(RENEW)) => self.renew(host).await?,
                }
            }
        }).await
    }
    pub async fn status(&self, host: &HostClient) -> Result<Value, PluginFault> {
        let (lease, _) = Self::read(host).await?;
        Ok(
            json!({"standby":self.standby.load(Ordering::SeqCst),"localOwner":lease.as_ref().is_some_and(|l| l.owner == self.owner && l.expires > now()),"expiresAt":lease.map(|l| l.expires)}),
        )
    }
    pub async fn standby(&self, host: &HostClient) -> Result<Value, PluginFault> {
        let (lease, version) = Self::read(host).await?;
        if lease.is_some_and(|l| l.owner == self.owner) {
            Self::put(
                host,
                &Lease {
                    owner: self.owner.clone(),
                    expires: 0,
                },
                version,
            )
            .await?;
        }
        self.standby.store(true, Ordering::SeqCst);
        self.status(host).await
    }
}
pub async fn check(host: &HostClient) -> Result<(), PluginFault> {
    let current = CURRENT
        .try_with(Arc::clone)
        .map_err(|_| fault("当前请求没有后台执行权"))?;
    current.check(host).await
}
