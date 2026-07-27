// 新领域教学助手 —— 后端服务（Node 内置模块 + 可选 pdf-parse 依赖）
// 职责：托管前端页面 + 作为 InfiniSynapse 适配层
// 登录方式：接入官方「使用 InfiniSynapse 登录」(Partner SSO)，访客用自己的 InfiniSynapse 账号登录，
//          后端拿到访客专属 API Key（记在访客自己账号下），消耗访客自己的额度，不花作者钱。
//
// 双模式入口：
//  - 本地直接运行 `node server.js`：起一个 HTTP 服务器监听端口（方便你本地调试）。
//  - 部署到 Vercel：Vercel 会 import 本文件的默认导出（handler）作为无服务器函数，
//    不会执行 listen，由 Vercel 接管请求。同一份代码两个环境都能跑。
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.INFINISYNAPSE_API_KEY; // 部署者自测兜底（可选，访客走登录）
const BASE = 'https://app.infinisynapse.cn';            // 业务接口（任务对话）域名
const ACCOUNT_API = 'https://api.infinisynapse.cn/api'; // 账号 / SSO 域名（与上面的 app 域名不同！）
const CLIENT_ID = process.env.INFINI_CLIENT_ID;
const CLIENT_SECRET = process.env.INFINI_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-insecure-change-me';
const PUBLIC_ORIGIN = process.env.PUBLIC_ORIGIN || ('http://localhost:' + PORT);
const MAX_BODY = 12 * 1024 * 1024; // 请求体上限 12MB（容纳 PDF 的 base64）
const MAX_CONTEXT = 30000;          // 喂给 AI 的资料文字上限，避免超长
const REPORT_FILE_NAME = 'study-plan.md'; // 让 AI 把最终计划写进工作区的固定文件，后端再读它回传

const SECURE_COOKIE = PUBLIC_ORIGIN.startsWith('https://');

// PDF 文字抽取：依赖可选，没装也能跑（此时 PDF 功能会提示先安装）
let pdfParse = null;
try { pdfParse = require('pdf-parse'); } catch {}

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// ---------- Cookie 与会话（加密，仅服务端能解密）----------
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach(p => {
    const idx = p.indexOf('=');
    if (idx < 0) return;
    const k = p.slice(0, idx).trim();
    const v = p.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  });
  return out;
}
function cookieFlags(maxAge) {
  let f = `Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
  if (SECURE_COOKIE) f += '; Secure';
  return f;
}
// 登录态加密存放在 http-only cookie 里：前端 JS 读不到，只在请求时由服务端解密。
// 注意：这把访客的专属 API Key 加密后存在 cookie，浏览器 JS 无法读取/外泄；符合"不在前端直连 InfiniSynapse"的安全底线。
function encryptSession(obj) {
  const key = crypto.createHash('sha256').update(SESSION_SECRET).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function decryptSession(b64) {
  if (!b64) return null;
  try {
    const key = crypto.createHash('sha256').update(SESSION_SECRET).digest();
    const buf = Buffer.from(b64, 'base64');
    const iv = buf.slice(0, 12);
    const tag = buf.slice(12, 28);
    const enc = buf.slice(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
    return JSON.parse(plain);
  } catch { return null; }
}

// ---------- 调用 InfiniSynapse 账号侧 SSO 接口 ----------
async function partnerReq(path, body) {
  const resp = await fetch(ACCOUNT_API + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Id': CLIENT_ID,
      'X-Client-Secret': CLIENT_SECRET,
    },
    body: JSON.stringify(body),
  });
  const json = await resp.json().catch(() => ({}));
  return { status: resp.status, json };
}

// 从 partner 接口返回的 JSON 里找授权/跳转地址（兼容字段名不确定的情况）
function pickEntryUrl(json) {
  if (!json) return null;
  const d = json.data;
  if (typeof d === 'string' && /^https?:\/\//.test(d)) return d;
  const candidates = ['entryUrl', 'url', 'authorizeUrl', 'authUrl', 'redirectUrl', 'loginUrl', 'link'];
  if (d && typeof d === 'object') {
    for (const k of candidates) if (typeof d[k] === 'string' && /^https?:\/\//.test(d[k])) return d[k];
  }
  for (const k of candidates) if (typeof json[k] === 'string' && /^https?:\/\//.test(json[k])) return json[k];
  return findInfiniUrl(json); // 兜底：递归找第一个像授权页的 URL
}
// 兜底：在返回 JSON 任意层级里找第一个像 InfiniSynapse 授权页的 URL
function findInfiniUrl(obj) {
  if (!obj || typeof obj !== 'object') return null;
  if (typeof obj === 'string') {
    if (/^https?:\/\/[^\s"']*infinisynapse\.(cn|com)[^\s"']*(auth|oauth|login|partner|sso|session)/i.test(obj)) return obj;
    return null;
  }
  for (const v of Object.values(obj)) {
    const r = findInfiniUrl(v);
    if (r) return r;
  }
  return null;
}

// 从 base64 抽取 PDF 文字
async function extractPdf(base64) {
  if (!pdfParse) {
    const e = new Error('PDF 解析需要依赖：请在项目目录运行一次 npm install，再上传 PDF（或改用 .txt/.md 教程，可免安装直接上传）');
    e.code = 'NO_PDF_DEP';
    throw e;
  }
  const buf = Buffer.from(base64, 'base64');
  const result = await pdfParse(buf);
  return (result.text || '').trim();
}

// 调用 InfiniSynapse：发任务 → 轮询任务工作区里的「报告文件」拿最终文字
// 关键修正：InfiniSynapse 的 AI 不会把最终答案塞进 messages 文本里，
// 而是把答案写成工作区根目录的一个 Markdown 文件（约定文件名见 REPORT_FILE_NAME）。
// 正确链路（来自官方 web-demo /agent-client.ts）：
//   发任务 → 轮询 getTaskWorkspace 看文件是否生成 → previewFile 读 data.content → 作为最终文字回传。
async function callInfini(text, taskId, apiKey) {
  if (!apiKey) throw new Error('未登录：请先点击「使用 InfiniSynapse 登录」登录后再使用（用你自己的额度，不花作者钱）');
  const authHeader = { 'Authorization': `Bearer ${apiKey}` };

  // 1) 新建 / 继续任务：taskId 自己生成（官方 demo 也是客户端生成），连同 connId 一起发
  const connId = uuid();
  const newTaskId = taskId || uuid();
  const body = {
    type: taskId ? 'askResponse' : 'newTask',
    taskId: newTaskId,
    text,
    connId,
  };
  if (!taskId) {
    // 新任务：开启自动审批，让 AI 自主跑完、把计划写进文件（不必等人点确认）
    body.images = [];
    body.autoApprovalSettings = {
      enabled: true,
      actions: { useMcp: true, useSandbox: true, useRag: true, useDatabase: true },
      maxRequests: 40,
      maxSubAgentRequests: 4,
      enableNotifications: true,
      enableWebSearch: true,
      enableReadImage: true,
      enableBrowser: false,
    };
    body.chatSettings = { mode: 'act' };
  } else {
    body.askResponse = 'messageResponse';
  }

  const msgResp = await fetch(`${BASE}/api/ai/message`, {
    method: 'POST',
    headers: { ...authHeader, 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  if (!msgResp.ok) {
    const errText = await msgResp.text().catch(() => '');
    throw new Error(`发送消息到 InfiniSynapse 失败，HTTP ${msgResp.status}：${errText.slice(0, 300) || '无返回内容'}`);
  }
  const msgJson = await msgResp.json().catch(() => ({}));
  // 统一信封：{ code:200, message:"success", data:{ success:true/false, ... } }
  if (msgJson && typeof msgJson.code === 'number' && msgJson.code !== 200) {
    throw new Error('InfiniSynapse 拒绝任务：' + (msgJson.message || '未知错误'));
  }
  const inner = msgJson.data || msgJson;
  if (inner && inner.success === false) {
    const note = inner.notification;
    const msg = note ? [note.title, note.message].filter(Boolean).join('：') : (inner.error || '任务提交被拒绝');
    throw new Error('InfiniSynapse 拒绝任务：' + msg);
  }

  // 2) 轮询任务工作区：等报告文件出现，再读取其内容
  let fullText = '';
  const POLL_INTERVAL = 2000;
  const MAX_POLLS = 26; // 约 53s，给 Vercel 60s 函数超时留余量
  for (let i = 0; i < MAX_POLLS; i++) {
    await new Promise(r => setTimeout(r, i === 0 ? 800 : POLL_INTERVAL));
    // 2a) 取工作区文件列表
    let files = [];
    try {
      const wsResp = await fetch(`${BASE}/api/ai_task/getTaskWorkspace/${encodeURIComponent(newTaskId)}`, {
        headers: authHeader
      });
      const wsJson = await wsResp.json().catch(() => ({}));
      const wsData = wsJson.data || wsJson;
      if (wsData && Array.isArray(wsData.files)) files = wsData.files.filter(f => typeof f === 'string');
    } catch {}
    // 2b) 报告文件存在就读取内容
    const hasReport = files.some(f => f === REPORT_FILE_NAME || f.endsWith('/' + REPORT_FILE_NAME));
    if (hasReport) {
      try {
        const pfResp = await fetch(`${BASE}/api/ai_task/previewFile`, {
          method: 'POST',
          headers: { ...authHeader, 'Content-Type': 'application/json' },
          body: JSON.stringify({ taskId: newTaskId, fileName: REPORT_FILE_NAME })
        });
        const pfJson = await pfResp.json().catch(() => ({}));
        const pfData = pfJson.data || pfJson;
        const content = (pfData && typeof pfData.content === 'string') ? pfData.content : '';
        if (content.trim()) { fullText = content; break; }
      } catch {}
    }
  }

  if (!fullText) {
    fullText = '（任务已结束，但工作区未找到结果文件，请到 InfiniSynapse 后台查看任务）';
  }
  return { reply: fullText, taskId: newTaskId, errored: false };
}

// 根据前端提交的内容，拼出给 AI 的学习指令
async function buildPrompt({ subject, pdfBase64, tutorialText, fileName }) {
  const parts = [];
  const subj = (subject || '').trim();
  parts.push(`我想学习的知识 / 领域：${subj || '（未填写，请基于下面资料自由发挥）'}`);

  let material = '';
  if (pdfBase64) {
    const pdfText = await extractPdf(pdfBase64);
    material += `我上传的学习资料《${fileName || '资料'}》（PDF 文档），其中内容如下：\n${pdfText}\n`;
  }
  if (tutorialText && tutorialText.trim()) {
    material += `我提供的教程内容：\n${tutorialText.trim()}\n`;
  }
  if (material) {
    if (material.length > MAX_CONTEXT) material = material.slice(0, MAX_CONTEXT) + '\n（资料较长，已截取前部分）';
    parts.push(material);
  } else {
    parts.push('（我暂时没有提供具体资料，请根据这个领域的一般学习路径来规划）');
  }

  const instruction = `\n请基于以上资料，为我列一份清晰、可直接照着执行的学习计划：按阶段或天数划分，说明每个阶段学什么、重点是什么、建议投入多少时间。如果资料不足，请结合该领域的通用学习路径来规划。用中文、条理清晰。

结果文件要求：
1. 必须在任务工作区根目录生成 Markdown 文件：${REPORT_FILE_NAME}
2. 文件内容就是上面这份学习计划本身。
3. 直接开始执行，不要只做空泛介绍。`;
  return parts.join('\n\n') + instruction;
}

// ---------- 请求处理函数（本地与 Vercel 共用）----------
async function handler(req, res) {
  // 托管前端页面
  if (req.method === 'GET' && (req.url === '/' || req.url === '/index.html')) {
    fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
      if (err) { res.writeHead(500); res.end('index.html 未找到'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  // ===== 登录相关路由（Partner SSO）=====
  // ① 发起登录：创建会话，把访客重定向到 InfiniSynapse 授权页
  if (req.method === 'GET' && req.url.startsWith('/login')) {
    if (!CLIENT_ID || !CLIENT_SECRET) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('未配置 SSO 凭证：请在 .env 填入 INFINI_CLIENT_ID 与 INFINI_CLIENT_SECRET（在 InfiniSynapse 设置 → 第三方接入 创建接入应用获取）。');
      return;
    }
    const state = crypto.randomBytes(16).toString('hex');
    let sess;
    try {
      sess = await partnerReq('/auth/partner/sessions', {
        returnUrl: PUBLIC_ORIGIN + '/auth/infini/callback',
        state,
      });
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('创建登录会话失败（网络错误，可能连不上 InfiniSynapse）：' + (e && e.message));
      return;
    }
    const { status, json } = sess;
    console.log('[partner/sessions] HTTP', status, 'code=', json && json.code, 'message=', json && json.message);
    // 统一信封：{ code:200, message:"success", data:{...} }，成功看 code===200（不是 HTTP 状态码）
    const ok = (json && (json.code === 200 || status === 200)) && (json.message === 'success' || json.code === 200);
    const entryUrl = pickEntryUrl(json);
    if (!ok || !entryUrl) {
      const errMsg = (json && (json.message || (json.data && json.data.message))) || ('HTTP ' + status);
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('创建登录会话失败：' + (errMsg === 'success' ? '接口返回成功，但未在返回里找到授权地址（请联系开发者看日志）' : errMsg));
      return;
    }
    res.writeHead(302, {
      'Location': entryUrl,
      'Set-Cookie': `xy_oauth_state=${state}; ${cookieFlags(600)}`,
    });
    res.end();
    return;
  }

  // ② 回调：校验 state，用一次性 code 换取用户信息 + 访客专属 API Key
  if (req.method === 'GET' && req.url.startsWith('/auth/infini/callback')) {
    const url = new URL(req.url, PUBLIC_ORIGIN);
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    const cookies = parseCookies(req.headers.cookie);
    if (!code || !state || state !== cookies.xy_oauth_state) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('登录校验失败（state 不匹配或缺少 code），请回到首页重新登录。');
      return;
    }
    if (!CLIENT_ID || !CLIENT_SECRET) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('未配置 SSO 凭证。');
      return;
    }
    let tok;
    try {
      tok = await partnerReq('/auth/partner/token', {
        code, grant_type: 'authorization_code', withApiKey: true,
      });
    } catch (e) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('换取用户信息失败（网络错误，可能连不上 InfiniSynapse）：' + (e && e.message));
      return;
    }
    const { status, json } = tok;
    console.log('[partner/token] HTTP', status, 'code=', json && json.code, 'hasApiKey=', !!(json && json.data && (json.data.apiKey || json.data.key || json.data.token)));
    const ok = (json && (json.code === 200 || status === 200)) && (json.message === 'success' || json.code === 200);
    if (!ok || !json.data) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('换取用户信息失败：' + ((json && (json.message || (json.data && json.data.message))) || ('HTTP ' + status)));
      return;
    }
    const user = json.data.user || json.user || {};
    const apiKey = json.data.apiKey || json.data.key || json.apiKey || json.data.token || json.token;
    if (!apiKey) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<p>登录成功，但未能签发你的专属 API Key（可能你的 InfiniSynapse API Key 数量已达上限 20 个）。</p>' +
        '<p>请到 app.infinisynapse.cn 左下角齿轮 → API Key 管理，删除一把（非「Partner:」开头的）后重试。</p>' +
        '<p><a href="/">返回首页</a></p>');
      return;
    }
    const session = encryptSession({
      id: user.id,
      nickname: user.nickname || user.username || '',
      email: user.email || '',
      apiKey,
      ts: Date.now(),
    });
    res.writeHead(302, {
      'Location': '/',
      'Set-Cookie': [
        `xy_session=${session}; ${cookieFlags(60 * 60 * 24 * 30)}`,
        `xy_oauth_state=; ${cookieFlags(0)}`,
      ],
    });
    res.end();
    return;
  }

  // ③ 前端查询当前登录态
  if (req.method === 'GET' && req.url.startsWith('/api/me')) {
    const cookies = parseCookies(req.headers.cookie);
    const s = decryptSession(cookies.xy_session);
    if (s && s.apiKey) {
      sendJson(res, 200, { loggedIn: true, user: { nickname: s.nickname, email: s.email } });
    } else {
      sendJson(res, 200, { loggedIn: false });
    }
    return;
  }

  // ④ 退出登录：清掉会话 cookie
  if (req.method === 'GET' && req.url.startsWith('/logout')) {
    res.writeHead(302, {
      'Location': '/',
      'Set-Cookie': `xy_session=; ${cookieFlags(0)}`,
    });
    res.end();
    return;
  }

  // 业务接口：前端调这个，由本服务端去调 InfiniSynapse（apiKey 来自登录态，不进前端）
  if (req.method === 'POST' && req.url === '/api/chat') {
    let body = '';
    let tooBig = false;
    req.on('data', c => {
      body += c;
      if (body.length > MAX_BODY) { tooBig = true; body = ''; req.destroy(); }
    });
    req.on('end', () => {
      if (tooBig) { sendJson(res, 413, { error: '提交内容过大，PDF 请控制在 10MB 以内' }); return; }
      // 用独立函数处理，确保任何异常都返回 JSON、不静默空响应
      handleChat(res, body, req).catch(e => {
        console.error('[api/chat] 未捕获异常:', (e && e.stack) || e);
        sendJson(res, 500, { error: '服务器内部错误：' + ((e && e.message) || e) });
      });
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
}

// 统一返回 JSON（已发过响应头则跳过，避免重复 writeHead 崩溃）
function sendJson(res, code, obj) {
  if (res.headersSent) return;
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

// 处理一次对话请求
async function handleChat(res, body, req) {
  let parsed;
  try { parsed = JSON.parse(body || '{}'); }
  catch { sendJson(res, 400, { error: '请求格式错误（不是合法 JSON）' }); return; }
  const { subject, pdfBase64, tutorialText, fileName, taskId } = parsed;
  // 优先用登录访客的专属 Key（访客自付额度），其次才用部署者环境变量兜底
  const cookies = parseCookies(req.headers.cookie);
  const session = decryptSession(cookies.xy_session);
  const apiKey = (session && session.apiKey) || API_KEY;
  if (!subject && !pdfBase64 && !(tutorialText && tutorialText.trim())) {
    sendJson(res, 400, { error: '请至少填写想学的知识、或上传 PDF / 教程' });
    return;
  }
  if (!apiKey) {
    sendJson(res, 401, { error: '请先点击「使用 InfiniSynapse 登录」登录后再使用（用你自己的额度，不花作者钱）。' });
    return;
  }
  const text = await buildPrompt({ subject, pdfBase64, tutorialText, fileName });
  const result = await callInfini(text, taskId, apiKey);
  sendJson(res, 200, result);
}

// 进程级兜底：任何未捕获异常/拒绝都打印到终端，便于排查
process.on('uncaughtException', e => console.error('[致命] 未捕获异常：', (e && e.stack) || e));
process.on('unhandledRejection', e => console.error('[致命] 未处理的 Promise 拒绝：', (e && e.stack) || e));

// ---------- 入口：本地起服务器 / Vercel 导出函数 ----------
// 本地直接运行（node server.js）：起 HTTP 服务器监听端口。
if (require.main === module) {
  http.createServer(handler).listen(PORT, () => {
    console.log(`新领域教学助手已启动： http://localhost:${PORT}`);
    if (CLIENT_ID && CLIENT_SECRET) {
      console.log('已启用「使用 InfiniSynapse 登录」(Partner SSO)。访客用自己的账号登录，消耗各自额度。');
    } else {
      console.log('提示：未配置 INFINI_CLIENT_ID / INFINI_CLIENT_SECRET，登录功能不可用。请在 .env 配置后重启。');
    }
    if (SESSION_SECRET === 'dev-only-insecure-change-me') {
      console.log('提示：当前使用默认的 SESSION_SECRET（仅本地调试用）。部署前请在 .env 设置一个随机长字符串。');
    }
    if (!pdfParse) console.log('提示：未安装 pdf-parse，PDF 上传功能暂不可用；运行 npm install 即可启用（.txt/.md 教程无需安装，可直接上传）。');
  });
}

// Vercel 部署时：把 handler 作为无服务器函数入口导出（此时不会执行上面的 listen）。
module.exports = handler;
module.exports.default = handler;
