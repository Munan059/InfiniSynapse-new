// Cloudflare Pages Functions —— 学习计划助手后端
// 这个文件是「总路由」：网站里所有 /api/*、/login、/auth/*、/logout 请求都由它处理。
// 网页本身（index.html + vendor/）由 Cloudflare Pages 直接托管，不会进到这里。
//
// 运行环境是 Cloudflare 的 Workers 运行时（不是 Node），所以没有 fs / require / node:crypto，
// 改用浏览器标准的 Web Crypto（crypto.subtle）做会话加密。
//
// 登录有两种模式（自动切换）：
//   1) SSO 模式：配置了 CLIENT_ID / CLIENT_SECRET 时，访客点「用 InfiniSynapse 登录」走官方授权，
//      拿到访客自己的专属 Key（记在加密 cookie 里），消耗访客自己的额度。
//   2) 贴 Key 模式：没配 SSO 凭证时，访客在网页里粘贴自己的 InfiniSynapse API Key，
//      直接拿去调 AI。Key 只存在访客自己浏览器 + 本次会话 cookie 里，作者看不到。

const BASE = 'https://app.infinisynapse.cn';            // 业务接口（任务对话）域名
const ACCOUNT_API = 'https://api.infinisynapse.cn/api'; // 账号 / SSO 域名
const REPORT_FILE_NAME = 'study-plan.md';               // 让 AI 把最终计划写进工作区的固定文件
const MAX_CONTEXT = 30000;                              // 喂给 AI 的资料文字上限
const MIN_ANSWER_LEN = 80;                             // 答案低于此长度几乎可确定是片段，不当最终结果

// ===================== 工具函数 =====================

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extra },
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

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

function redirect(location, cookies = []) {
  const h = new Headers();
  h.set('Location', location);
  for (const c of cookies) h.append('Set-Cookie', c);
  return new Response(null, { status: 302, headers: h });
}

function cookieFlags(maxAge, more = '') {
  return `Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${maxAge}${more}`;
}

// ===================== 会话加密（Web Crypto / AES-GCM）=====================
// 把访客的 Key 加密后存进 http-only cookie，前端 JS 读不到、外泄不了。

async function deriveKey(secret) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(secret || 'dev-only-insecure'));
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function bytesToBase64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function encryptSession(obj, secret) {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const out = new Uint8Array(iv.length + ct.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ct), iv.length);
  return bytesToBase64(out);
}

async function decryptSession(b64, secret) {
  if (!b64) return null;
  try {
    const bytes = base64ToBytes(b64);
    const iv = bytes.slice(0, 12);
    const ct = bytes.slice(12);
    const key = await deriveKey(secret);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return JSON.parse(new TextDecoder().decode(pt));
  } catch {
    return null;
  }
}

// ===================== 调用 InfiniSynapse 账号侧 SSO 接口 =====================

async function partnerReq(path, body, env) {
  const resp = await fetch(ACCOUNT_API + path, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Client-Id': env.CLIENT_ID,
      'X-Client-Secret': env.CLIENT_SECRET,
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
  return findInfiniUrl(json);
}

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

// ===================== 调 AI 的两条取结果路径（官方 10.4/10.5）=====================
//   A) 工作区文件：getTaskWorkspace 发现 .md → previewFile 读 content（最完整，优先）
//   B) UI 消息：getUiMessageById 取最新一条 partial!==true 的消息 text（兜底）

// 判断一条消息是不是「用户发出的请求 / 提示词回声」（要跳过，不能当答案）
function isRequestMessage(m) {
  if (!m || typeof m !== 'object') return false;
  if (m.request != null) return true;
  const t = typeof m.text === 'string' ? m.text : '';
  if (!t) return false;
  if (t.startsWith('{"request"')) return true;
  if (t.includes('<task>')) return true;
  if (t.includes('结果文件要求') && t.includes('study-plan.md')) return true;
  if (t.includes('我上传的学习资料') || t.includes('我提供的教程内容')) return true;
  return false;
}

// 判断是不是 AI 的「思考 / 规划过程」（内心独白，不是最终交付物）
function isThinkingMessage(m) {
  const t = (typeof m.text === 'string' ? m.text : '').trim();
  if (!t) return false;
  if (t.length >= 400) return false;
  const low = t.toLowerCase();
  const thinkPrefixes = ['用户想要', '用户希望', '我需要', '让我先', '让我来', '我打算', '我计划', '我将', '接下来我', '首先我', '根据您', '基于您', '好的，', '收到，', '现在我来', '让我分析'];
  return thinkPrefixes.some(p => low.startsWith(p));
}

// 从 UI 消息数组里取最终答案：跳过请求/思考/ask，取最长的一条有文字消息
function extractAnswerFromMessages(arr) {
  if (!Array.isArray(arr) || !arr.length) return '';
  const candidates = arr.filter(m =>
    m && typeof m === 'object' &&
    !isRequestMessage(m) &&
    !isThinkingMessage(m) &&
    m.type !== 'ask' &&
    typeof m.text === 'string' && m.text.trim()
  );
  if (!candidates.length) return '';
  candidates.sort((a, b) => b.text.trim().length - a.text.trim().length);
  const ans = candidates[0].text.trim();
  if (ans.startsWith('{"request"') || (ans.includes('结果文件要求') && ans.includes('study-plan.md'))) return '';
  return ans;
}

// 从 getTaskWorkspace 的 files 结构里抽出所有文件名（兼容多种结构）
function collectFiles(wsData) {
  const out = [];
  const walk = (node) => {
    if (!node) return;
    if (typeof node === 'string') { out.push(node); return; }
    if (Array.isArray(node)) { node.forEach(walk); return; }
    if (typeof node === 'object') {
      const nm = node.path || node.name || node.fileName || (typeof node.title === 'string' ? node.title : '');
      if (typeof nm === 'string' && nm) out.push(nm);
      if (Array.isArray(node.files)) node.files.forEach(walk);
      if (Array.isArray(node.children)) node.children.forEach(walk);
    }
  };
  if (wsData && wsData.files !== undefined) walk(wsData.files);
  else walk(wsData);
  return [...new Set(out)];
}

// ① 发任务：POST 到 /api/ai/message 开新任务，立刻返回 taskId（很快，不会超时）
async function callInfiniStart(text, apiKey) {
  if (!apiKey) throw new Error('未登录：请先登录或粘贴你的 API Key 再生成（用你自己的额度）。');
  const authHeader = { 'Authorization': `Bearer ${apiKey}` };
  const newTaskId = crypto.randomUUID();
  const connId = crypto.randomUUID();
  const body = {
    type: 'newTask',
    taskId: newTaskId,
    text,
    connId,
    images: [],
    autoApprovalSettings: {
      enabled: true,
      actions: { useMcp: true, useSandbox: true, useRag: true, useDatabase: true },
      maxRequests: 40,
      maxSubAgentRequests: 4,
      enableNotifications: true,
      enableWebSearch: true,
      enableReadImage: true,
      enableBrowser: false,
    },
    chatSettings: { mode: 'act' },
  };
  const msgResp = await fetch(`${BASE}/api/ai/message`, {
    method: 'POST',
    headers: { ...authHeader, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!msgResp.ok) {
    const errText = await msgResp.text().catch(() => '');
    throw new Error(`发送消息到 InfiniSynapse 失败，HTTP ${msgResp.status}：${errText.slice(0, 300) || '无返回内容'}`);
  }
  const msgJson = await msgResp.json().catch(() => ({}));
  if (msgJson && typeof msgJson.code === 'number' && msgJson.code !== 200) {
    throw new Error('InfiniSynapse 拒绝任务：' + (msgJson.message || '未知错误'));
  }
  const inner = msgJson.data || msgJson;
  if (inner && inner.success === false) {
    const note = inner.notification;
    const msg = note ? [note.title, note.message].filter(Boolean).join('：') : (inner.error || '任务提交被拒绝');
    throw new Error('InfiniSynapse 拒绝任务：' + msg);
  }
  return newTaskId;
}

// ② 单轮轮询：内部做 2 次短检查（共约 3 秒），返回当前最佳结果与是否完成。
//    前端会反复调用这个接口，直到 done=true，避免单次请求长时间挂起被掐断。
async function callInfiniPoll(taskId, apiKey) {
  const authHeader = { 'Authorization': `Bearer ${apiKey}` };
  let bestMsgText = '';
  let completed = false;
  let fileText = '';

  for (let i = 0; i < 2; i++) {
    await sleep(i === 0 ? 1500 : 1800);

    // 检查 UI 消息（兜底取答案）
    try {
      const uiResp = await fetch(`${BASE}/api/ai_task/getUiMessageById?id=${encodeURIComponent(taskId)}`, { headers: authHeader });
      const uiJson = await uiResp.json().catch(() => ({}));
      const uiData = (uiJson && uiJson.data !== undefined) ? uiJson.data : uiJson;
      const arr = Array.isArray(uiData) ? uiData
        : (uiData && Array.isArray(uiData.messages) ? uiData.messages : []);
      if (!completed) {
        completed = arr.some(m =>
          m && (
            (m.say === 'completion_result') ||
            (m.ask === 'completion_result') ||
            (m.type === 'say' && m.completion_result) ||
            (m.type === 'ask' && m.completion_result)
          )
        );
      }
      const candidate = extractAnswerFromMessages(arr);
      if (candidate && candidate.length > bestMsgText.length) bestMsgText = candidate;
    } catch (e) {
      console.error('[取消息失败]', (e && e.message) || e);
    }

    // 检查工作区 .md 文件（最可靠的交付物）
    try {
      const wsResp = await fetch(`${BASE}/api/ai_task/getTaskWorkspace/${encodeURIComponent(taskId)}`, { headers: authHeader });
      const wsJson = await wsResp.json().catch(() => ({}));
      const wsData = wsJson.data || wsJson;
      const fileList = collectFiles(wsData);
      const md = fileList.find(f => f.split('/').pop() === REPORT_FILE_NAME)
              || fileList.find(f => f.toLowerCase().endsWith('.md'));
      if (md) {
        const pfResp = await fetch(`${BASE}/api/ai_task/previewFile`, {
          method: 'POST',
          headers: { ...authHeader, 'Content-Type': 'application/json' },
          body: JSON.stringify({ taskId, fileName: md }),
        });
        const pfJson = await pfResp.json().catch(() => ({}));
        const pfData = pfJson.data || pfJson;
        if (pfData && typeof pfData.content === 'string') fileText = pfData.content.trim();
      }
    } catch (e) {
      console.error('[取文件失败]', (e && e.message) || e);
    }

    if (fileText) break;
  }

  let done = false, reply = '';
  if (fileText) { done = true; reply = fileText; }
  else if (completed && bestMsgText.length >= MIN_ANSWER_LEN) { done = true; reply = bestMsgText; }
  else { done = false; reply = bestMsgText; }

  return { done, reply, completed, bestLen: bestMsgText.length };
}

// 根据提交内容，拼出给 AI 的学习指令（PDF 文字已在浏览器端抽好，这里只收文本）
async function buildPrompt({ subject, pdfText, tutorialText, fileName }) {
  const parts = [];
  const subj = (subject || '').trim();
  parts.push(`我想学习的知识 / 领域：${subj || '（未填写，请基于下面资料自由发挥）'}`);

  let material = '';
  if (pdfText && pdfText.trim()) {
    material += `我上传的学习资料《${fileName || '资料'}》（PDF 文档），其中内容如下：\n${pdfText.trim()}\n`;
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

重要（务必遵守）：
1. 把上面这份完整的学习计划写入工作区根目录的 Markdown 文件：${REPORT_FILE_NAME}，这是你要交付的成果，用户最终看到的就是这个文件的内容。
2. 不要在对话消息里复述资料原文，也不要输出你的思考 / 规划过程（例如"用户想要我…""我需要…""让我先…"这类内部独白）。对话里只需一句简短确认（如"学习计划已生成，见 ${REPORT_FILE_NAME}"）即可。
3. 直接开始执行，不要只做空泛介绍。`;
  return parts.join('\n\n') + instruction;
}

// ===================== 各路由处理函数 =====================

// /api/me —— 前端加载时问后端是否登录
async function apiMe(request, env) {
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const s = await decryptSession(cookies.xy_session, env.SESSION_SECRET);
  if (s && s.apiKey) {
    return json({ loggedIn: true, mode: 'sso', user: { nickname: s.nickname, email: s.email } });
  }
  // 没 SSO 会话：前端可能处于「自己贴 Key」模式（Key 存在它自己浏览器里，这里不知道）
  return json({ loggedIn: false, ssoEnabled: !!(env.CLIENT_ID && env.CLIENT_SECRET) });
}

// /api/chat —— 前端点「生成」时调用：开新任务，返回 taskId（很快）
async function apiChat(request, env) {
  let parsed;
  try { parsed = await request.json(); } catch { return json({ error: '请求格式错误（不是合法 JSON）' }, 400); }
  const { subject, pdfText, tutorialText, fileName, apiKey } = parsed;

  // Key 优先级：SSO 会话 cookie > 请求体里带的 Key（贴 Key 模式）> 环境变量兜底
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const session = await decryptSession(cookies.xy_session, env.SESSION_SECRET);
  const key = (session && session.apiKey) || apiKey || env.INFINISYNAPSE_API_KEY;

  if (!subject && !pdfText && !(tutorialText && tutorialText.trim())) {
    return json({ error: '请至少填写想学的知识、或上传 PDF / 教程' }, 400);
  }
  if (!key) {
    const tip = (env.CLIENT_ID && env.CLIENT_SECRET)
      ? '请先点「使用 InfiniSynapse 登录」登录后再使用（用你自己的额度）。'
      : '请先在登录框里粘贴你的 InfiniSynapse API Key，或在后台配置 INFINISYNAPSE_API_KEY。';
    return json({ error: tip }, 401);
  }

  const text = await buildPrompt({ subject, pdfText, tutorialText, fileName });
  const taskId = await callInfiniStart(text, key);

  // 贴 Key 模式进来的：种一个会话 cookie，方便后续轮询用同一把 Key（SSO 模式本来就有 cookie）
  const extra = {};
  if (!session && apiKey) {
    const cookie = await encryptSession({ apiKey, ts: Date.now() }, env.SESSION_SECRET);
    extra['Set-Cookie'] = `xy_session=${cookie}; ${cookieFlags(1800)}`;
  }
  return json({ taskId }, 200, extra);
}

// /api/poll?taskId=xxx —— 前端轮询：单轮检查，返回当前最佳结果与是否完成
async function apiPoll(request, env) {
  const url = new URL(request.url);
  const taskId = url.searchParams.get('taskId');
  if (!taskId) return json({ error: '缺少 taskId' }, 400);

  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const session = await decryptSession(cookies.xy_session, env.SESSION_SECRET);
  const apiKey = (session && session.apiKey) || env.INFINISYNAPSE_API_KEY;
  if (!apiKey) return json({ done: true, reply: '', error: '会话已失效，请重新生成。' });

  try {
    const r = await callInfiniPoll(taskId, apiKey);
    return json(r);
  } catch (e) {
    return json({ done: true, reply: '', error: (e && e.message) || String(e) });
  }
}

// /login —— 发起 SSO 登录（仅在配置了 CLIENT_ID/CLIENT_SECRET 时可用）
async function login(request, env) {
  if (!env.CLIENT_ID || !env.CLIENT_SECRET) {
    return new Response(
      '未配置 SSO 凭证（CLIENT_ID / CLIENT_SECRET）。请到 Cloudflare 后台的 Pages 环境变量里填写，或使用「粘贴自己的 Key」模式。',
      { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    );
  }
  const origin = new URL(request.url).origin;
  const state = [...crypto.getRandomValues(new Uint8Array(8))].map(b => b.toString(16).padStart(2, '0')).join('');
  let sess;
  try {
    sess = await partnerReq('/auth/partner/sessions', { returnUrl: origin + '/auth/infini/callback', state }, env);
  } catch (e) {
    return new Response('创建登录会话失败（网络错误，可能连不上 InfiniSynapse）：' + (e && e.message), { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  const { status, json: j } = sess;
  const ok = (j && (j.code === 200 || status === 200)) && (j.message === 'success' || j.code === 200);
  const entryUrl = pickEntryUrl(j);
  if (!ok || !entryUrl) {
    const errMsg = (j && (j.message || (j.data && j.data.message))) || ('HTTP ' + status);
    return new Response('创建登录会话失败：' + errMsg, { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  return redirect(entryUrl, [`xy_oauth_state=${state}; ${cookieFlags(600)}`]);
}

// /auth/infini/callback —— SSO 回调：校验 state，用 code 换访客专属 Key，写进加密 cookie
async function authCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  if (!code || !state || state !== cookies.xy_oauth_state) {
    return new Response('登录校验失败（state 不匹配或缺少 code），请回到首页重新登录。', { status: 400, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  if (!env.CLIENT_ID || !env.CLIENT_SECRET) return new Response('未配置 SSO 凭证。', { status: 500, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });

  let tok;
  try {
    tok = await partnerReq('/auth/partner/token', { code, grant_type: 'authorization_code', withApiKey: true }, env);
  } catch (e) {
    return new Response('换取用户信息失败（网络错误，可能连不上 InfiniSynapse）：' + (e && e.message), { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  const { status, json: j } = tok;
  const ok = (j && (j.code === 200 || status === 200)) && (j.message === 'success' || j.code === 200);
  if (!ok || !j.data) {
    return new Response('换取用户信息失败：' + ((j && (j.message || (j.data && j.data.message))) || ('HTTP ' + status)), { status: 502, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  }
  const user = j.data.user || j.user || {};
  const apiKey = j.data.apiKey || j.data.key || j.apiKey || j.data.token || j.token;
  if (!apiKey) {
    return new Response(
      '<p>登录成功，但未能签发你的专属 API Key（可能你的 InfiniSynapse API Key 数量已达上限）。</p>' +
      '<p>请到 app.infinisynapse.cn 左下角齿轮 → API Key 管理，删除一把（非「Partner:」开头的）后重试。</p>' +
      '<p><a href="/">返回首页</a></p>',
      { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } }
    );
  }
  const session = await encryptSession({ id: user.id, nickname: user.nickname || user.username || '', email: user.email || '', apiKey, ts: Date.now() }, env.SESSION_SECRET);
  return redirect('/', [
    `xy_session=${session}; ${cookieFlags(60 * 60 * 24 * 30)}`,
    `xy_oauth_state=; ${cookieFlags(0)}`,
  ]);
}

// /logout —— 清掉会话 cookie
async function logout() {
  return redirect('/', [`xy_session=; ${cookieFlags(0)}`]);
}

// ===================== 总入口 =====================
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  try {
    if (request.method === 'GET' && path === '/api/me') return await apiMe(request, env);
    if (request.method === 'POST' && path === '/api/chat') return await apiChat(request, env);
    if (request.method === 'GET' && path === '/api/poll') return await apiPoll(request, env);
    if (request.method === 'GET' && path.startsWith('/login')) return await login(request, env);
    if (request.method === 'GET' && path.startsWith('/auth/infini/callback')) return await authCallback(request, env);
    if (request.method === 'GET' && path.startsWith('/logout')) return await logout(env);

    // 兜底：凡是 GET 请求（且不是上面的接口），先试着按原路径找静态文件，
    // 找不到就回退到 index.html 首页，避免出现「Not found」空白页。
    if (request.method === 'GET') {
      try {
        const tryPath = path === '/' ? '/index.html' : path;
        const asset = await env.ASSETS.fetch(new URL(tryPath, url.origin).toString());
        if (asset && asset.ok) return asset;
      } catch { /* 忽略，继续往下走 */ }
      try {
        const idx = await env.ASSETS.fetch(new URL('/index.html', url.origin).toString());
        if (idx && idx.ok) return idx;
      } catch { /* 忽略 */ }
    }
    return new Response('Not found', { status: 404 });
  } catch (e) {
    console.error('[未捕获异常]', (e && e.stack) || e);
    return json({ error: '服务器内部错误：' + ((e && e.message) || String(e)) }, 500);
  }
}
