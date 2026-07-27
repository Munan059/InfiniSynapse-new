# 新领域教学助手

参加 InfiniSynapse × CSDN「Vibe Coding 泛数据分析应用开发大赛」的作品。

**它干嘛的**：输入你想学的知识（一个领域/主题），上传教材 PDF 或教程，手把手带你学——拆成每天计划、标重点、出思考题，你每天打卡，它跟踪进度、提醒下一步。

**登录方式**：接入官方「**使用 InfiniSynapse 登录**」(Partner SSO)。访客点一下跳去 InfiniSynapse 官网用**自己的账号**授权登录，后端拿到该访客的专属 API Key（记在访客自己账号下），之后调用消耗的是**访客自己的额度，不花作者钱**。访客的 Key 只在服务端、加密存放在 http-only cookie 里，前端 JS 读不到，符合"不在前端直连 InfiniSynapse"的安全底线。

---

## 一、申请接入凭证（一次性，约 2 分钟）

1. 登录 https://app.infinisynapse.cn/tasks （用你自己的 InfiniSynapse 账号）。
2. 左下角齿轮 → **第三方接入** → **创建接入应用**。
   - 应用名称：`新领域教学助手`
   - 回调域名白名单：`localhost` 和你的部署域名 `xxx.vercel.app`（多个用逗号分隔；本地调试先填 `localhost`，部署时再加线上域名）
3. 创建成功弹窗里复制 `clientId` / `clientSecret`（**只显示一次**，存好）。

> 这一步是开发者（你）做的，访客（朋友/评委）不需要申请，他们只需在网页点"登录"用各自的 InfiniSynapse 账号授权即可。

---

## 二、本地运行（开发 / 自测）

1. 安装 Node.js（版本 ≥ 18）。
2. 把 `.env.example` 复制为 `.env`，填入：
   ```
   INFINI_CLIENT_ID=你申请的clientId
   INFINI_CLIENT_SECRET=你申请的clientSecret
   SESSION_SECRET=任意一长串随机字符
   PUBLIC_ORIGIN=http://localhost:3000
   ```
3. 安装依赖（PDF 上传功能需要；只用 .txt/.md 教程可跳过）：
   ```
   npm install
   ```
4. 启动：
   ```
   node server.js
   ```
5. 浏览器打开 http://localhost:3000 → 点「使用 InfiniSynapse 登录」→ 跳去官网授权 → 跳回即可使用（消耗你自己的额度）。

---

## 三、功能说明

- **想学的知识**：填一个领域/主题（如「机器学习入门」），不传资料 AI 也按通用路径规划。
- **上传 PDF**：选 PDF 教材，服务端抽取文字后发给 AI（需 `npm install`）。
- **上传教程**：选 `.txt` / `.md`，自动读入文字。
- **粘贴文字**：也可直接在文本框粘贴教程内容。
- **打卡跟踪**：学完第几天点「下一步学什么」，AI 给复习与下一步建议（多轮对话靠 taskId 续接）。
- **额度**：所有调用都按登录访客身份发起，记在访客自己的 InfiniSynapse 账号下、耗访客额度。

---

## 四、部署上线（拿公网网址，纯网页操作）

1. 注册 GitHub（你账号 Munan059），网页 **New repository** 新建仓库。
2. 把本目录文件上传到仓库（网页拖拽/上传）：
   - **不要上传 `.env`**（里面是你的 clientSecret）；只上传 `.env.example` 和代码文件。
   - `package.json` 含 `pdf-parse` 依赖，Vercel 会自动 `npm install`。
3. 注册 Vercel（https://vercel.com，GitHub 登录），**Add New → Project → Import** 你的仓库 → Deploy。
4. 在 Vercel **Settings → Environment Variables** 配 3 个变量（都是服务端用，不会暴露给前端）：
   - `INFINI_CLIENT_ID` = 你的 clientId
   - `INFINI_CLIENT_SECRET` = 你的 clientSecret
   - `SESSION_SECRET` = 一长串随机字符（与本地不同也行）
   - `PUBLIC_ORIGIN` = `https://你的域名.vercel.app`（部署完成后 Vercel 给的地址）
5. 回到 InfiniSynapse **设置 → 第三方接入 → 编辑你的接入应用**，把 `xxx.vercel.app` 加进回调域名白名单。
6. 重新 Deploy，拿到 `xxx.vercel.app`，打开能用即可。

> 无需在 Vercel 配 `INFINISYNAPSE_API_KEY`：访客各自登录、各用各额度，不花你的钱，也最安全。

---

## 五、绑定自己的域名（子域名，可选但推荐）

比赛要求作品有"公网能打开的网址"。Vercel 给的 `xxx.vercel.app` 已经能用、能提交；但你想用自己域名下的子域名（如 `study.你的域名.com`），按下面做。你域名的 DNS 在 Cloudflare 管理，Spaceship 只是买域名的地方，不用动。

> 前提：代码已按第四节部署成功，拿到 `xxx.vercel.app`。

1. **Vercel 里登记子域名**
   - Vercel 项目 → **Settings → Domains**
   - 输入子域名，例如 `study.你的域名.com`（`study` 可换成任意前缀）
   - 点 **Add**，Vercel 会显示需要去 DNS 加的记录（通常是：`CNAME`，名字 `study`，目标 `cname.vercel-dns.com`）。

2. **去 Cloudflare 加这条解析记录**（这就是"生成子域名"的动作）
   - 登录 dash.cloudflare.com → 左上选你的域名 → 左侧 **DNS → Records**
   - 点 **Add record**：
     - Type：`CNAME`
     - Name：`study`（只填前缀，别填全域名）
     - Target：`cname.vercel-dns.com`
     - TTL：`Auto`
     - Proxy status：首次选 **DNS only（灰色云朵）**，能访问后再考虑橙色云（加速）
   - **Save**。

3. **等生效**：几分钟到几小时。回到 Vercel 的 Domains 页，状态变绿（Active）即成功，Vercel 自动签发 HTTPS 证书。此时访问 `study.你的域名.com` 就能打开应用。

4. **回 InfiniSynapse 加白名单**（不然登录会被拦）
   - app.infinisynapse.cn → 齿轮 → **第三方接入** → 编辑「新领域教学助手」
   - 把 `study.你的域名.com` 加进**回调域名白名单**（本地 `localhost` 和 `xxx.vercel.app` 也留着）。

5. **把环境变量 `PUBLIC_ORIGIN` 改成子域名**
   - Vercel → Settings → Environment Variables → 把 `PUBLIC_ORIGIN` 改为 `https://study.你的域名.com` → 重新 Deploy。
   - （不改也勉强能用，但登录回调拼接的 returnUrl 会以 vercel.app 为准，建议改准。）

---

## 六、报名提交

打开 https://infinisynapse.cn/contest/vibe-coding/register ，填写：
- 应用名：新领域教学助手
- 简介：输入想学的知识 + 上传教材/教程（PDF 或 .txt/.md），生成 7 天学习计划、重点与思考题，支持打卡跟踪进度；访客用 InfiniSynapse 账号登录后使用，消耗各自额度
- 作品网址：你的 `xxx.vercel.app`
- 接口集成说明：接入「使用 InfiniSynapse 登录」(Partner SSO)，访客授权后后端以其专属 API Key 调用 InfiniSynapse Server API（先 `GET /api/ai/events` 建 SSE，再 `POST /api/ai/message` 发 newTask/askResponse 生成学习计划并多轮追问）
- 代码仓库：（可选）

---

## 七、文件说明

- `server.js`：后端服务（托管页面 + Partner SSO 登录路由 + 加密会话 + PDF 抽取 + 调 InfiniSynapse）
- `index.html`：前端页面（登录入口、输入知识、上传 PDF/教程、计划展示、打卡、进度）
- `.env.example`：接入凭证模板（复制为 .env 填真实值，勿上传 .env）
- `vercel.json`：Vercel 部署配置
- `package.json`：项目元信息（含 pdf-parse 依赖）

---

## 八、安全与注意

- 访客的专属 API Key 加密存放在 http-only cookie，浏览器 JS 读不到；建议生产环境全程 HTTPS（Vercel 默认满足）。
- 访客第一次登录后，其 InfiniSynapse 账号的 API Key 列表里会多出一把 `Partner: 新领域教学助手`，可随时吊销；吊销后下次登录会自动重新签发。
- 若某访客提示"未能签发专属 API Key"，多半是其 API Key 数量达上限（默认 20 个），引导其删一把非 Partner 开头的即可。
- `SESSION_SECRET` 务必用随机长串，且只放服务端环境变量，别写进前端或公开仓库。
