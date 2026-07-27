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

// 调用 InfiniSynapse：发任务 → 轮询"工作区文件"和"UI 消息"两条路，哪条先拿到答案用哪条
// 官方给出两条取最终结果的路子（Server API Reference 10.4/10.5）：
//   A) 工作区文件：getTaskWorkspace 发现 .md → previewFile 读 data.content（最完整，优先）
//   B) UI 消息：getUiMessageById 取最新一条 partial!==true 的消息 text（兜底，不依赖 AI 写文件）
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
    // 新任务：开启自动审批，让 AI 自主跑完（不必等人点确认）
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

  // 2) 轮询两条路：文件优先，消息兜底（但必须等任务真正完成或结果可靠才返回）
  //
  // 官方文档（10.5 组合原则）明确：
  //   - 任务完成的标志是 completion_result 信号（message.say/ask = completion_result）
  //   - getUiMessageById 返回的是"精简 UI 消息"，仅用于恢复界面，不应作为最终交付物
  //   - 交付物应优先用工作区文件（getTaskWorkspace + previewFile）
  //
  // 之前的 bug：只要 extractAnswerFromMessages 返回任何非空字符串就立即 break，
  //            导致 AI 正在生成的 partial 片段（如"用户想要我基于..."半句话）被当答案提前返回。
  // 修复：引入 completion_result 检测 + 最小答案长度门槛 + "耐心等待文件"策略。
  let fullText = '';
  let lastDiag = '';
  const POLL_INTERVAL = 2000;
  const MAX_POLLS = 35;       // 约 70s（Vercel Pro 上限 60s 时可适当调低；Hobby 10s 则靠前端重试）
  const MIN_ANSWER_LEN = 80;  // 答案低于此长度几乎可以确定是 partial 片段，不作为最终结果
  let bestMsgText = '';       // 记住轮询过程中见过的最长合法消息（兜底用）
  let completed = false;      // 是否检测到 completion_result 完成信号

  for (let i = 0; i < MAX_POLLS; i++) {
    await new Promise(r => setTimeout(r, i === 0 ? 800 : POLL_INTERVAL));

    // 2a) 检测任务是否已完成（completion_result 信号）
    try {
      const uiResp = await fetch(`${BASE}/api/ai_task/getUiMessageById?id=${encodeURIComponent(newTaskId)}`, {
        headers: authHeader
      });
      const uiJson = await uiResp.json().catch(() => ({}));
      const uiData = (uiJson && uiJson.data !== undefined) ? uiJson.data : uiJson;
      const arr = Array.isArray(uiData) ? uiData
        : (uiData && Array.isArray(uiData.messages) ? uiData.messages : []);

      // 检查是否有 completion_result 完成信号（官方推荐的任务完成标志）
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

      // 提取候选答案消息（跳过回声和 ask 类型）
      const candidate = extractAnswerFromMessages(arr, text);
      if (candidate && candidate.length > bestMsgText.length) {
        bestMsgText = candidate; // 始终保留最长的那条
      }
      lastDiag = `消息数=${arr.length} 完成=${completed} 最佳消息长=${bestMsgText.length}`;
    } catch (e) {
      console.error('[取消息失败]', (e && e.message) || e);
    }

    // 2b) 工作区 .md 文件（最可靠的交付物，官方首推）
    let fileText = '';
    try {
      const wsResp = await fetch(`${BASE}/api/ai_task/getTaskWorkspace/${encodeURIComponent(newTaskId)}`, {
        headers: authHeader
      });
      const wsJson = await wsResp.json().catch(() => ({}));
      const wsData = wsJson.data || wsJson;
      const fileList = collectFiles(wsData);
      lastDiag += ` | 文件数=${fileList.length}`;
      const md = fileList.find(f => f.split('/').pop() === REPORT_FILE_NAME)
              || fileList.find(f => f.toLowerCase().endsWith('.md'));
      if (md) {
        const pfResp = await fetch(`${BASE}/api/ai_task/previewFile`, {
          method: 'POST',
          headers: { ...authHeader, 'Content-Type': 'application/json' },
          body: JSON.stringify({ taskId: newTaskId, fileName: md })
        });
        const pfJson = await pfResp.json().catch(() => ({}));
        const pfData = pfJson.data || pfJson;
        if (pfData && typeof pfData.content === 'string') fileText = pfData.content.trim();
      }
    } catch (e) {
      console.error('[取文件失败]', (e && e.message) || e);
    }

    // ===== 退出条件判断（核心修复）=====
    if (fileText) {
      // 有文件 → 最可靠，立即返回
      fullText = fileText;
      break;
    }

    if (completed) {
      // 已检测到 completion_result 但还没拿到文件 → 再等一轮让文件写入（AI 刚标记完成，文件可能还在写磁盘）
      if (i < MAX_POLLS - 3) {
        await new Promise(r => setTimeout(r, 1500)); // 多等 1.5s
        continue; // 下一轮重新尝试取文件
      }
      // 最后几轮了，实在没文件就用最佳消息
      if (bestMsgText.length >= MIN_ANSWER_LEN) {
        fullText = bestMsgText;
        break;
      }
    }

    // 未完成状态：即使有消息也不轻易返回（避免 partial 片段被当答案）
    // 只有消息足够长且已经轮询了较长时间（给 AI 充足生成时间）才考虑接受
    if (!completed && bestMsgText.length >= MIN_ANSWER_LEN && i >= Math.floor(MAX_POLLS * 0.6)) {
      // 已经等了很久、消息也够长，可能是 AI 不写文件的情况（纯对话式回答）
      // 再等两轮看看会不会出文件
      if (i >= MAX_POLLS - 3) {
        fullText = bestMsgText;
        break;
      }
    }
  }

  if (!fullText) {
    // 最终都没拿到可靠结果
    if (bestMsgText.length > 0) {
      // 有消息但不满足长度/完成条件 → 可能是超时了，把能拿到的最好结果返回（带提示）
      fullText = bestMsgText + '\n\n（注：以上内容可能不完整，建议到 InfiniSynapse 后台查看完整结果）';
    } else {
      console.error('[诊断] 轮询结束未取到答案。', lastDiag);
      fullText = '（任务已结束，但既没在工作区找到结果文件，也没在消息里取到最终答案，请到 InfiniSynapse 后台查看任务）';
    }
  }
  return { reply: fullText, taskId: newTaskId, errored: false };
}

// 判断一条消息是不是"用户发出的请求 / 提示词回声"（要跳过，不能当答案）
function isRequestMessage(m, sentText) {
  if (!m || typeof m !== 'object') return false;
  if (m.request != null) return true;                                  // 官方把用户请求包在 request 字段里
  const t = typeof m.text === 'string' ? m.text : '';
  if (!t) return false;
  if (t.startsWith('{"request"')) return true;                         // 回声也是请求
  if (t.includes('<task>')) return true;                               // 早期的 task 包裹格式
  // 我们的指令签名：只会出现在我们发出的提示词里，"真实学习计划"里绝不会同时出现这两句
  if (t.includes('结果文件要求') && t.includes('study-plan.md')) return true;
  // buildPrompt 拼的引导语：资料回显的特征，真实答案不会这么写
  if (t.includes('我上传的学习资料') || t.includes('我提供的教程内容')) return true;
  // 兜底：收到的消息基本就是发出的那一整段提示词（回声），按开头 120 字精确比对
  if (sentText) {
    const norm = s => s.replace(/\s+/g, '');
    const a = norm(sentText), b = norm(t);
    if (a && b && b.length >= a.length * 0.85 && a.slice(0, 120) === b.slice(0, 120)) return true;
  }
  return false;
}

// 判断一条消息是不是 AI 的"思考 / 规划过程"（内心独白，不是最终交付物，不能当答案）
// 典型特征：以"用户想要我…""我需要…""让我先…"开头，且篇幅较短（真正的计划很长）
function isThinkingMessage(m) {
  const t = (typeof m.text === 'string' ? m.text : '').trim();
  if (!t) return false;
  // 只在较短时判定为思考过程，避免误伤长答案
  if (t.length >= 400) return false;
  const low = t.toLowerCase();
  const thinkPrefixes = ['用户想要', '用户希望', '我需要', '让我先', '让我来', '我打算', '我计划', '我将', '接下来我', '首先我', '根据您', '基于您', '好的，', '收到，', '现在我来', '让我分析'];
  return thinkPrefixes.some(p => low.startsWith(p));
}

// 从 UI 消息数组里取最终答案：跳过请求消息、思考过程、ask 类型，
// 取【最长】的一条有文字消息（真正的学习计划通常最长最完整；思考过程/片段都较短）
function extractAnswerFromMessages(arr, sentText) {
  if (!Array.isArray(arr) || !arr.length) return '';
  const candidates = arr.filter(m =>
    m && typeof m === 'object' &&
    !isRequestMessage(m, sentText) &&
    !isThinkingMessage(m) &&
    m.type !== 'ask' &&
    typeof m.text === 'string' && m.text.trim()
  );
  if (!candidates.length) return '';
  // 取最长的一条作为答案（真实计划/答案通常最长最完整）
  candidates.sort((a, b) => b.text.trim().length - a.text.trim().length);
  const ans = candidates[0].text.trim();
  // 兜底：万一还是取到了请求（极少），丢弃
  if (ans.startsWith('{"request"') || (ans.includes('结果文件要求') && ans.includes('study-plan.md'))) return '';
  return ans;
}

// 从 getTaskWorkspace 的 files 结构里抽出所有文件名（兼容 字符串数组 / 对象数组 / 树状结构）
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
  else walk(wsData); // 兜底：files 可能直接在 data 根
  return [...new Set(out)];
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

重要（务必遵守）：
1. 把上面这份完整的学习计划写入工作区根目录的 Markdown 文件：${REPORT_FILE_NAME}，这是你要交付的成果，用户最终看到的就是这个文件的内容。
2. 不要在对话消息里复述资料原文，也不要输出你的思考 / 规划过程（例如"用户想要我…""我需要…""让我先…"这类内部独白）。对话里只需一句简短确认（如"学习计划已生成，见 ${REPORT_FILE_NAME}"）即可。
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
