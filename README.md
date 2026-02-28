# CForum

一个基于 Cloudflare Workers + Pages + D1 + R2 的论坛，支持帖子、评论、图片上传、2FA 等。

**💡 性能优化**：采用 Pages + Worker 混合部署，静态资源免费无限请求，节省 ~90% Worker 成本！

---

## 🏗️ 架构设计

### 单域名 + 智能网关方案

```
用户访问：forum.adysec.com
         ↓
    Cloudflare Pages（Edge 网络）
         ↓
  ┌─ Pages Functions 判断路由
  │
  ├─ /api/* ?
  │  ├─ YES → 转发给 Worker（处理业务逻辑 + 数据库）
  │  │         返回 JSON
  │  │
  │  └─ NO  → 返回静态文件或 index.html
  │           前端 React Router 接管
  │
  └─ 用户看到页面
```

## ✨ 功能特性

- ✅ **帖子管理** - 发布、编辑、删除、置顶、分类
- ✅ **评论系统** - 多级评论、支持回复
- ✅ **用户认证** - 注册、登录、邮件验证、2FA
- ✅ **图片上传** - 图片直接上传到 R2，支持 Markdown 预览
- ✅ **用户资料** - 头像上传、个人资料、邮件通知设置
- ✅ **管理后台** - 用户管理、分类管理、设置管理
- ✅ **访问统计** - 浏览量统计（post view count）
- ✅ **点赞系统** - 灵活的点赞/取消点赞
- ✅ **验证码** - 集成 Cloudflare Turnstile
- ✅ **邮件服务** - SMTP 配置、验证邮件、重置密码

## 🚀 快速开始

### 方法 1：Fork + 一键部署（适合一次部署的普通用户）

[![Deploy to Cloudflare](https://camo.githubusercontent.com/aa3de9a0130879a84691a2286f5302105d5f3554c5d0af4e3f2f24174eeeea25/68747470733a2f2f6465706c6f792e776f726b6572732e636c6f7564666c6172652e636f6d2f627574746f6e)](https://deploy.workers.cloudflare.com/?url=https://github.com/adysec/cforum)

> 在 Cloudflare 仪表盘中为 Worker 添加一个至少 32 字符的 `JWT_SECRET` 密钥。
> **前端提醒**：如果 Worker 运行时未检测到有效 `JWT_SECRET`，页面顶部将显示黄色通知并建议一个随机密钥，你可以复制并粘贴到 Secrets 中。

### 方法 2：GitHub Actions 自动部署（推荐）

项目已内置 `.github/workflows/deploy.yml`，每次推送到 `main` 分支或手动触发时自动构建并部署到 Cloudflare。

#### 第一步：获取 Cloudflare API Token

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 **My Profile > API Tokens**
3. 点击 **Create Token**
4. 配置自定义权限：
   - **Account > Workers Scripts** - Edit
   - **Account > D1** - Edit
   - **Account > R2** - Edit
   - **Account > Pages** - Edit
5. 选择你的账户，点击 **Continue to summary**
6. 创建后复制 Token（只会显示一次）
<img width="1778" height="506" alt="图片" src="https://github.com/user-attachments/assets/0f7f179b-d2a9-4f3b-8981-f736d294898a" />

#### 第二步：获取 Account ID

1. 在 Cloudflare Dashboard 首页，选择任意域名
2. 右侧栏可以看到 **Account ID**，复制它

#### 第三步：配置 GitHub Secrets

在你的 GitHub 仓库中：
1. 进入 **Settings > Secrets and variables > Actions**
2. 点击 **New repository secret**，添加以下密钥：

| Secret 名称 | 值 | 描述 | 是否必需 |
|-----------|----|----|----|
| `CF_API_TOKEN` | Cloudflare API Token | [创建CF_API_TOKEN](https://dash.cloudflare.com/profile/api-tokens) | 必需 |
| `CF_ACCOUNT_ID` | 你的 Cloudflare Account ID | [查看CF_ACCOUNT_ID](https://dash.cloudflare.com/caching/overview) | 必需 |
| `JWT_SECRET` | 随机字符串 | `head -c 32 /dev/urandom \| base64` | 必需 |
| `SMTP_HOST` | SMTP 服务器地址 | 邮件发送用，例如：smtp.exmail.qq.com | 非必需，未配置则无法注册 |
| `SMTP_PORT` | SMTP 端口 | 例如：465 | 非必需，未配置则无法注册 |
| `SMTP_USER` | SMTP 用户名 | 邮箱地址 | 非必需，未配置则无法注册 |
| `SMTP_PASS` | SMTP 密码 | 应用专用密码（非主密码） | 非必需，未配置则无法注册 |
| `SMTP_FROM` | 发送者邮箱 | 例如：noreply@example.com（未设置则使用 SMTP_USER） | 非必需，未配置则无法注册 |
| `SMTP_FROM_NAME` | 发件人显示名称 | 例如：CForum（未设置则使用"论坛管理员"） | 非必需，未配置则无法注册 |
| `BASE_URL` | 站点 URL | 例如：`https://forum.adysec.com`（未设置则自动使用当前请求域名） | 非必需，未配置则邮件异常 |
| `TURNSTILE_SITE_KEY` | Cloudflare Turnstile Site Key | [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile) | 非必需，未配置则使用Turnstile |
| `TURNSTILE_SECRET_KEY` | Cloudflare Turnstile Secret | [Cloudflare Turnstile](https://dash.cloudflare.com/?to=/:account/turnstile) | 非必需，未配置则使用Turnstile |
<img width="2244" height="1350" alt="图片" src="https://github.com/user-attachments/assets/77b109a9-ebb6-4e9d-a660-0828e28c5bd1" />

#### 第四步：手动触发部署

在 GitHub 仓库的 **Actions** 页面：
1. 选择 **Deploy to Cloudflare** workflow
2. 点击 **Run workflow**
3. 选择 `main` 分支并确认

---

## 🌐 自定义域名配置（可选）

### 单域名方案（推荐）

CForum 采用 **Pages + Worker 混合架构，通过 Pages Functions 统一接入**：

```
用户访问：https://forum.adysec.com
    ↓
Cloudflare Pages CDN (智能路由)
    ├─ /api/* → Pages Functions 代理 → Worker (D1/R2)
    └─ 其他   → 返回静态文件 (index.html → 前端路由)
```

**优点**：
- ✅ 用户只需一个域名
- ✅ 完全自动化，无需手动配置 Worker 域名
- ✅ Pages 托管静态资源（免费）
- ✅ Worker 隐身在后面（免费额度 10w/d）

### 绑定步骤

1. 进入 [Cloudflare Dashboard](https://dash.cloudflare.com/) → **Pages**
2. 选择 **cforum** 项目 → **Settings** → **Custom domains**
3. 点击 **Add custom domain**，输入你的域名（如 `forum.adysec.com`）
4. 完成验证 ✅

**默认管理员账号**（首次登录后请立即修改！）：
- 邮箱: `admin@adysec.com` / 密码: `Admin@123`

## 📄 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 🙋 支持

- 💬 欢迎提交 Issue 和 Pull Request
- 🌟 如果有帮助，请 Star 本项目！
