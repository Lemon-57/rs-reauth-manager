# 账号重新授权

RS 网关独立插件，通过原账号备注中的 `邮箱----密码----2FA` 完成协议登录，沿用该账号绑定的代理，成功后将新授权写回原账号

**当前状态：实验性功能**，已完成离线协议、前端及制品校验，并在 RS v3.26.2 验证安装、管理页加载、真实账号列表、筛选和分页，尚未用真实账号验证完整登录与写回链路，请先在测试实例和自有测试账号上验证，不建议直接批量操作生产账号

![模拟数据界面](docs/screenshots/overview-dark.png)

截图为模拟数据，不包含真实账号资料

## 安装

在 [Releases](https://github.com/Lemon-57/rs-reauth-manager/releases) 下载对应版本的 `.tar.gz` 与 `.sha256`，核对摘要后，在 RS 的插件管理中上传安装

也可以使用 GitHub 来源安装，仓库填写 `Lemon-57/rs-reauth-manager`，标签留空查询最新已公开发行版，选择插件 `.tar.gz` 附件，不是 GitHub 自动生成的 Source code 归档

| 项目 | 范围 |
| --- | --- |
| 插件 ID | `personal.reauth-manager` |
| 当前源码版本 | `0.1.11`，公开版本以 Releases 为准 |
| 宿主兼容清单 | `>=3.26.2, <3.28.0` |
| 制品平台 | Linux x86_64，插件入口要求 glibc 2.28+ |
| 账号范围 | 全部套餐的 ChatGPT OAuth 账号，包含 Free |
| 功能入口 | 扩展页中的“账号重新授权” |

暂不提供 ARM64、Windows 或 macOS 宿主安装包，前端可由桌面和手机浏览器访问

## 使用

1. 在 RS 原账号备注中填写 `邮箱----密码----2FA`，两处分隔符都是四个连字符，2FA 是 Base32 验证器密钥，不是当前六位动态码
2. 确认备注邮箱与原账号邮箱一致，并已绑定该账号自己的代理
3. 在插件中搜索或筛选账号，单号执行或勾选后批量提交，确认后进入串行队列
4. 查看处理进度及结果，失败、结果不确定或中断时先核对原账号，再手动决定是否重试

支持会员和状态筛选、10/20/50/100 条分页、选择当前页、停止队列及单号取消
账号后显示 RS 原生分组，多个分组全部列出，没有分组时显示“未分组”；搜索支持分组名称，展示不修改账号分组配置
顶部“可处理”按全部适用账号中 RS 状态为异常的账号数统计，包含备注或代理尚未齐全的账号；这类账号仍须补齐资料并空闲后才能提交
“成功”和“未完成”只统计本页最近一次提交的任务，单号和批量提交均会开始新的一次统计；重新进入插件或刷新整个页面时归零，不删除后台历史记录
点击“成功”或“未完成”会列出本次对应账号并清除无关搜索、会员筛选和分页位置；普通读取最新账号不会清空本次结果
“队列”仍显示后台实际排队及运行中的任务数，重新进入页面不会取消已有任务或将其结果混入本次统计
Free、Plus、Pro、Team、Business 等全部套餐的 OAuth 账号均可列出、筛选和重新授权；API Key 或其他提供商账号不适用这个登录协议
缺少代理或登录资料时仍拒绝执行，不回退到直连或其他账号代理；本插件的账号范围与周限／重置卡插件独立，后者的 Free 排除规则不受影响
原工作区在已登录会话中确认不可用，且唯一明确的个人工作区确认为同一用户的 Free 时，使用上游协议获取新的 Free 授权，停用原 RS 账号后通过公开 SDK 写回原账号，不新建账号、不修改分组
完整读回验证通过后显示“登录成功：原工作区已失效，已切回 Free，已停止调度”，计入本次成功；无法确认身份或工作区时不降级，停用或写回结果不确定时显示需要核对且不自动重试

## 安全与边界

### 管理员强制写回其他工作区

当任务因“无法匹配原账号工作区，已停止写回”失败时，账号操作列提供“强制写回”入口。
新失败任务只保存从已登录会话提取的工作区 ID，不保存 RT、密码、2FA 或代理认证。
管理员必须选择一个明确工作区，并勾选“替换原授权并停止调度”后，才会创建逐号强制授权任务；默认不选工作区、不勾选确认，也不提供批量强制开关。
旧失败任务没有工作区列表时，先点击“重新检测工作区”走常规登录，取得列表后再打开强制写回确认。

强制任务会重新登录，复用原代理，使用独立 PKCE 换取所选工作区的授权；仍校验同一邮箱、用户身份、授权主体、工作区和令牌有效期，不允许把其他用户的 RT 写入此账号。
新工作区可以是 Free、Plus、Team 等套餐，以实际验证的新授权为准。写回前检查账号空闲、配置及凭据版本未变，然后停止该号调度，精确版本写回原记录并读回验证；保留名称、备注、分组、代理、权重、并发和模型权限。
停止调度或写回结果不确定时显示“需要核对”，不自动重复登录或写回，也不自动恢复调度。
此功能允许管理员明确替换工作区身份，属于新增行为，源码版本为 0.1.10；网站更新与 GitHub Release 分别处理，已发布附件保持不变。

- 安装使用 `trustedProcess`，意味着完整信任插件，不是操作系统沙箱，请审查源码和发行包来源
- 密码、2FA、完整代理地址和一次性回调只在内存与私有进程管道中传输，不写入任务状态、普通日志或页面
- 常规授权由 RS 原生 OAuth 流程交换和保存 RT；已验证的 Free 恢复使用未修改的上游换取令牌协议，并通过 RS 公开 `host.auth.save` 精确凭据版本校验写回，RT 只经过私有管道与 SDK 二进制载荷，不在页面展示、下载或导出
- 为读取带认证代理，后台按精确单账号调用 RS 原生敏感导出接口，只取代理 URL，不持久化或向前端提供导出的凭据
- 保留原账号的名称、分组、代理、权重、并发限制和模型权限，不启用、不改组，也不使用重置卡；常规授权保留启用状态，Free 恢复或管理员确认强制替换工作区时关闭该账号调度，原本停用的账号仍停用
- 登录和写回前必须观测到账号在途请求为零，状态未知时停止，这不是跨系统流量锁，持续接收新请求的账号需要管理员选择空闲窗口
- 登录期间配置或凭据版本变化时停止写回，工作区无法确认时停止，不默认选择第一个工作区；管理员确认只放宽原工作区匹配要求，不放宽用户身份、并发与凭据版本检查
- 不绕过手机号、验证码或其他人工验证要求，遇到这些步骤时需要人工处理
- 取消可以终止尚未提交的协议进程和后续任务，不能撤销已经提交的授权，进程重启及不确定结果不会自动重放登录
- 每次最多排队 100 个账号，串行执行，单号超时 420 秒，不提供定时自动重登

请仅处理自己拥有或明确获授权的账号，并遵守服务条款

## 协议与上游

协议模块来自 [boji1334/reauth-web](https://github.com/boji1334/reauth-web)，固定提交 `db8251817fd1baefc83c14c851135fb6078bc001`
仅保留登录必需的五个 `vendor/lib` 模块与 RFC 6238 TOTP 实现，不依赖重登站，不包含兑换、支付、账号注册或其 Web 服务
原模块保持不变，适配代码在 `protocol/runner.py`，原始 MIT 许可位于 `protocol/LICENSE.reauth-web`
适配层接受 RS 返回的官方桌面授权外层链接，仅拆出并校验 `authorize_url` 后交给上游协议；常规路径不重新生成或替换 RS 的 state、PKCE、client_id 和回调地址，也支持直接 OAuth 链接
只有已验证的 Free 恢复路径使用上游 `generate_pkce` 生成独立的 state 和 PKCE，保留已校验的 client_id 与回调地址，复用同一代理及登录会话；绝不拿 RS 待完成流程的授权码搭配其他 verifier 交换

后端使用 RS v3.26.2 的公开 SDK，固定提交 `ae5eaa46b447548571e6c46d69bd27d454adb785`
界面使用官方 `@codex-proxy/ui` v0.4.1 编译发行包，并参考 [插件工作台示例](https://github.com/zyycn/codex-proxy-plugins) 组织公开宿主桥、请求层、业务解码和 composable
不跨仓导入宿主内部源码，不读取管理 Cookie，也不直接访问宿主数据库

第三方来源与许可见 [NOTICE](legal/NOTICE.md) 和各协议、依赖的原始许可

## 本地开发

需要 Rust 1.97.0、Node.js 24+、pnpm 9.12.2 和 Python 3.11+
所有编译、依赖准备及打包均应在本机完成，不在生产应用服务器执行

```bash
pnpm --dir frontend install --frozen-lockfile
pnpm --dir frontend build
node verification/bridge-test.mjs
node verification/batch-test.mjs
node verification/conventions.mjs
cargo +1.97.0 fmt --manifest-path backend/Cargo.toml --check
cargo +1.97.0 clippy --manifest-path backend/Cargo.toml --all-targets --locked -- -D warnings
cargo +1.97.0 build --manifest-path backend/Cargo.toml --locked
node verification/protocol-test.mjs
python -B -m unittest discover -s verification -p 'test_*.py' -v
```

Windows 使用已配置到 PATH 的 `python`，Linux 使用 `python3`，也可以通过 `RS_REAUTH_TEST_PYTHON` 指定离线测试解释器
测试全部使用模拟宿主和虚构账号，不访问真实上游

`pnpm --dir frontend dev` 启动模拟数据预览，开发模式不代表已安装到 RS，也不会向真实账号发起授权

## 构建安装包

Linux 协议运行环境包含在发行包内，安装者无需在服务器装 Python 或依赖
运行包展开到宿主解出的插件目录中的随机私有子目录，权限为 0700，插件进程正常退出时清理；强制终止或宿主崩溃可能留下运行目录
该数据盘需可写、可执行并至少预留 256 MiB 空间，不依赖系统 `/tmp` 的容量或执行权限，不修改网关的只读根目录、挂载与 CPU/内存配置
登录前会先解包并检查 Python、TLS、协议依赖、TOTP 和离线桌面授权链接解析契约，失败时不会发起原生授权流程
管理员可通过已注册管理路由 `POST api/runtime-check`、正文 `{}` 单独执行自检，自检不读取登录资料、不访问上游、不创建账号任务

本地准备 Python 依赖及 [crane v0.20.6](https://github.com/google/go-containerregistry/releases/tag/v0.20.6)，然后执行

```bash
python -m pip install -r requirements-dev.txt
python scripts/prepare_runtime.py --crane /path/to/crane
python scripts/build_runtime.py
```

准备脚本按固定镜像摘要下载 Linux x86_64 Python 基础镜像，不需要 Docker daemon，不访问应用服务器
wheel 版本与 SHA-256 固定在 `protocol/requirements-linux.txt`，构建时校验镜像各层，并按 ELF 依赖闭包打包
缓存默认位于仓库内 `.cache/runtime`，不会提交到 Git
已有公开输入时可以用 `build_runtime.py --base-tar <file> --dependencies-dir <directory>` 指定其路径

Linux 原生构建示例

```bash
cargo +1.97.0 build --manifest-path backend/Cargo.toml --release --locked --target x86_64-unknown-linux-gnu
cpr-plugin package --manifest plugin.json --binary backend/target/x86_64-unknown-linux-gnu/release/reauth-manager --target x86_64-unknown-linux-gnu --resource-map web=frontend/dist --output-dir dist
python scripts/verify_artifact.py
```

Windows 交叉编译需先配置 Zig 与 cargo-zigbuild，将构建命令换成 `cargo +1.97.0 zigbuild --manifest-path backend/Cargo.toml --release --locked --target x86_64-unknown-linux-gnu.2.28`
`cpr-plugin` 使用与上文 SDK 相同的固定提交构建，生成的制品及校验文件位于 `dist/`

## 验证范围

包含 29 项真实 SDK 子进程协议场景、5 项账号范围及运行目录测试、17 项 Python 适配层测试、4 项未修改上游 OAuth 代码的离线传输集成测试、9 项 Free 恢复身份保护与真实上游 PKCE/交换代码测试、5 项 HTML 资源回归测试、12 项前端桥与响应解码测试、14 项 Vue 生命周期、本次任务统计与分组搜索场景，以及公开依赖、SFC、主题和资源边界检查
已进行本机 Linux 交叉编译、官方 CLI 打包、内部摘要校验和模拟页面的明暗主题及窄屏检查，发行包检查会拒绝不受宿主支持的 HTML 资源引用
已在 RS v3.26.2 实际安装并验证管理页、真实账号列表、会员筛选、页容量切换和窄屏布局，iframe 保持原有隔离策略
v0.1.4 已在无网络、非 root、只读根目录和 32 MiB `noexec` 临时盘的隔离环境验证真实运行包解压、依赖自检、目录复用及正常退出清理，并通过实际宿主的环境自检；这些检查不读取账号登录资料、不访问上游、不执行真实账号授权或写回
v0.1.5 已在相同隔离条件下、128 MiB 内存和 0.25 CPU 限额内使用安装包内运行环境通过 21 项适配层及原始上游协议集成测试，并在 RS v3.27.1 验证版本切换、环境自检、管理页和账号列表；旧插件已排空，账号配置及插件历史保持不变
v0.1.9 已在相同隔离条件下通过 30 项适配层、原始上游协议与 Free 恢复测试，并在 RS v3.27.1 验证实际版本切换及环境自检；安装未触发真实账号登录，账号配置、历史记录和其他插件保持不变，Free 恢复的完整真实账号链路仍待验证
这些结果不等于已经验证真实账号可完成授权，代理、账号状态、工作区和人工验证都可能导致实际登录失败
