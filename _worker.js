// MoonTV Register Bot - 完整整合版 Cloudflare Worker
// 环境变量（env）：BOT_TOKEN, ADMIN_ID, MOONTVURL, APIURL, USERNAME, PASSWORD, GROUP_ID, NEXT_PUBLIC_SITE_NAME
// KV binding: env.KV

const USER_AGENT = "CF-Workers-MoonTVRegisterBot/cmliu";

/* --------------------- 通用工具 --------------------- */

function nowISO() { return new Date().toISOString(); }

function safeJsonParse(s) {
  try { return JSON.parse(s); } catch (e) { return null; }
}

function extractBaseUrl(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch (e) {
    return url;
  }
}

function getLatencyStatus(responseTime) {
  if (responseTime === null || responseTime === undefined) return '未知';
  if (responseTime < 300) return '良好';
  if (responseTime < 1000) return '一般';
  return '拥挤';
}

/* --------------------- 发送消息 --------------------- */

async function sendMessage(botToken, chatId, text, options = {}) {
  try {
    const payload = { chat_id: String(chatId), text, parse_mode: 'HTML' };
    if (options.reply_markup) payload.reply_markup = options.reply_markup;
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.error('sendMessage error:', e);
  }
}

async function getBotInfo(botToken) {
  try {
    const r = await fetch(`https://api.telegram.org/bot${botToken}/getMe`);
    if (!r.ok) return null;
    const j = await r.json();
    return j.ok ? j.result : null;
  } catch (e) {
    console.error('getBotInfo error:', e);
    return null;
  }
}

/* --------------------- 获取最新 APP 版本（可选按钮） --------------------- */

async function getLatestAppRelease() {
  try {
    const r = await fetch('https://api.github.com/repos/MoonTechLab/Selene/releases/latest', {
      headers: { 'User-Agent': USER_AGENT }
    });
    if (!r.ok) return null;
    const j = await r.json();
    return { version: j.tag_name, downloadUrl: j.html_url };
  } catch (e) {
    console.error('getLatestAppRelease error:', e);
    return null;
  }
}

/* --------------------- Cookie 与 MoonTV API 辅助 ---------------------
KV usage:
  KV.put('cookie', <rawCookieJsonString>)
  KV.get('cookie') -> raw cookie json string
------------------------------------------------------------ */

async function getCookie(apiUrl, username, password, KV) {
  try {
    // 检查 KV 缓存
    const cached = await KV.get('cookie');
    if (cached) {
      try {
        const obj = JSON.parse(cached);
        const ts = obj.timestamp || 0;
        if (Date.now() - ts < 432000000) { // 5 days
          const final = encodeURIComponent(encodeURIComponent(cached));
          return `auth=${final}`;
        }
      } catch (e) {
        console.log('cookie parse failed, will re-login', e.message);
      }
    }

    // 登录获取 cookie
    const loginRes = await fetch(`${apiUrl.replace(/\/$/, '')}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
      body: JSON.stringify({ username, password })
    });

    if (!loginRes.ok) throw new Error(`login HTTP ${loginRes.status}`);
    const loginJson = await loginRes.json();
    if (!loginJson.ok) throw new Error('login returned not ok');

    // 优先尝试从 Set-Cookie 头解析
    const setCookie = loginRes.headers.get('set-cookie');
    if (setCookie) {
      const m = setCookie.match(/auth=([^;]+)/);
      if (m) {
        const encoded = m[1];
        try {
          const dec1 = decodeURIComponent(encoded);
          const dec2 = decodeURIComponent(dec1);
          const cookieObj = JSON.parse(dec2);
          cookieObj.timestamp = cookieObj.timestamp || Date.now();
          const raw = JSON.stringify(cookieObj);
          await KV.put('cookie', raw);
          const final = encodeURIComponent(encodeURIComponent(raw));
          return `auth=${final}`;
        } catch (e) {
          console.warn('cookie decode/json failed', e.message);
        }
      }
    }

    // 如果 API 返回了 cookie 字段
    if (loginJson.cookie) {
      const obj = { ...(loginJson.cookie), timestamp: Date.now() };
      const raw = JSON.stringify(obj);
      await KV.put('cookie', raw);
      return `auth=${encodeURIComponent(encodeURIComponent(raw))}`;
    }

    throw new Error('unable to extract cookie from login response');
  } catch (e) {
    console.error('getCookie error:', e);
    throw e;
  }
}

async function checkUserExists(apiUrl, username, password, KV, targetUsername) {
  try {
    const cookie = await getCookie(apiUrl, username, password, KV);
    const r = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/config`, {
      method: 'GET',
      headers: { 'Cookie': cookie, 'User-Agent': USER_AGENT }
    });
    if (!r.ok) throw new Error(`config HTTP ${r.status}`);
    const j = await r.json();
    const users = j.Config?.UserConfig?.Users || [];
    return users.some(u => String(u.username) === String(targetUsername));
  } catch (e) {
    console.error('checkUserExists error:', e);
    return false;
  }
}

/* --------------------- 注册 /start / 修改密码 / 状态 --------------------- */

async function generateInitialPassword(userId) {
  const timestamp = Date.now();
  const rawText = `${userId}${timestamp}`;
  try {
    const buf = await crypto.subtle.digest('MD5', new TextEncoder().encode(rawText));
    const arr = Array.from(new Uint8Array(buf));
    return arr.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 8);
  } catch (e) {
    return Math.random().toString(36).slice(-8);
  }
}

async function handleStartCommand(botToken, userId, chatId, chatType, GROUP_ID, apiUrl, moontvUrl, username, password, KV, siteName) {
  try {
    // 群聊中提示私聊
    if (chatType === 'group' || chatType === 'supergroup') {
      const bi = await getBotInfo(botToken);
      const botUsername = bi?.username || 'bot';
      await sendMessage(botToken, chatId, `🔐 为了保护您的账户安全，请私聊机器人进行注册：@${botUsername}`);
      return;
    }

    // 如配置了 GROUP_ID，则检查是否在群组中
    if (GROUP_ID) {
      const inGroup = await checkUserInGroup(botToken, GROUP_ID, userId);
      if (!inGroup) {
        const gname = await getGroupName(botToken, GROUP_ID);
        await sendMessage(botToken, chatId, `⚠️ 当前用户无注册权限，只允许 ${gname} 群组内部人员注册。`);
        return;
      }
    }

    // 查询是否已存在
    const exists = await checkUserExists(apiUrl, username, password, KV, userId.toString());
    const appInfo = await getLatestAppRelease();
    if (!exists) {
      const initialPassword = await generateInitialPassword(userId);
      await sendMessage(botToken, chatId, "⏳ 正在为您注册账户，请稍等...");
      let success = false;
      let lastErr = null;
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          const cookie = await getCookie(apiUrl, username, password, KV);
          const addR = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': cookie, 'User-Agent': USER_AGENT },
            body: JSON.stringify({
              targetUsername: userId.toString(),
              targetPassword: initialPassword,
              action: 'add'
            })
          });
          if (!addR.ok) throw new Error(`add user HTTP ${addR.status}`);
          const addJ = await addR.json();
          if (!addJ.ok) throw new Error('add user API returned not ok');
          await new Promise(r => setTimeout(r, 1000));
          const created = await checkUserExists(apiUrl, username, password, KV, userId.toString());
          if (created) { success = true; break; }
        } catch (e) {
          lastErr = e;
          console.error('register attempt error:', e);
          if (attempt < 3) await new Promise(r => setTimeout(r, 2000));
        }
      }

      if (!success) {
        await sendMessage(botToken, chatId, `❌ 注册失败，请联系管理员。\n错误: ${lastErr?.message || '未知'}`);
        return;
      }

      const serviceName = siteName || 'MoonTV';
      const msg = `✅ 注册成功！\n\n🌐 <b>服务器：</b><code>${moontvUrl}</code>\n🆔 <b>用户名：</b><code>${userId}</code>\n🔑 <b>访问密码：</b><code>${initialPassword}</code>\n\n💡 使用 <code>/pwd</code> 修改密码\n`;
      const reply_markup = appInfo ? { inline_keyboard: [[{ text: `📱 下载 APP ${appInfo.version}`, url: appInfo.downloadUrl }]] } : undefined;
      await sendMessage(botToken, chatId, msg, reply_markup ? { reply_markup } : undefined);
      return;
    } else {
      const msg = `ℹ️ 你已注册过账户\n\n🌐 <b>服务器：</b><code>${moontvUrl}</code>\n🆔 <b>用户名：</b><code>${userId}</code>\n\n💡 使用 <code>/pwd</code> 修改密码`;
      await sendMessage(botToken, chatId, msg);
      return;
    }
  } catch (e) {
    console.error('handleStartCommand error:', e);
    await sendMessage(botToken, chatId, '❌ 操作失败，请稍后再试。');
  }
}

async function handlePasswordCommand(botToken, userId, chatId, chatType, GROUP_ID, newPassword, apiUrl, moontvUrl, username, password, KV, siteName) {
  try {
    if (chatType === 'group' || chatType === 'supergroup') {
      const bi = await getBotInfo(botToken);
      const bn = bi?.username || 'bot';
      await sendMessage(botToken, chatId, `🔐 请私聊机器人修改密码：@${bn}`);
      return;
    }

    if (GROUP_ID) {
      const inGroup = await checkUserInGroup(botToken, GROUP_ID, userId);
      if (!inGroup) {
        const gname = await getGroupName(botToken, GROUP_ID);
        await sendMessage(botToken, chatId, `⚠️ 当前用户无权限，只允许 ${gname} 群组内部人员使用。`);
        return;
      }
    }

    if (!newPassword || newPassword.length < 6) {
      await sendMessage(botToken, chatId, "❌ 密码长度至少6位，请重新输入。");
      return;
    }

    const exists = await checkUserExists(apiUrl, username, password, KV, userId.toString());
    if (!exists) {
      await sendMessage(botToken, chatId, "❌ 用户未注册，请先使用 /start 注册账户。");
      return;
    }

    try {
      const cookie = await getCookie(apiUrl, username, password, KV);
      const changeR = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Cookie': cookie, 'User-Agent': USER_AGENT },
        body: JSON.stringify({
          targetUsername: userId.toString(),
          targetPassword: newPassword,
          action: 'changePassword'
        })
      });
      if (!changeR.ok) throw new Error(`changePassword HTTP ${changeR.status}`);
      const changeJ = await changeR.json();
      if (!changeJ.ok) throw new Error('changePassword returned not ok');
      await sendMessage(botToken, chatId, `✅ 密码修改成功！\n🆔 <code>${userId}</code>\n🔑 <code>${newPassword}</code>`);
      return;
    } catch (e) {
      console.error('handlePasswordCommand api error:', e);
      await sendMessage(botToken, chatId, `❌ 密码修改失败: ${e.message}`);
      return;
    }
  } catch (e) {
    console.error('handlePasswordCommand error:', e);
    await sendMessage(botToken, chatId, '❌ 操作失败，请稍后再试。');
  }
}

async function handleStateCommand(botToken, userId, chatId, GROUP_ID, apiUrl, moontvUrl, username, password, KV, siteName) {
  try {
    if (GROUP_ID) {
      const inGroup = await checkUserInGroup(botToken, GROUP_ID, userId);
      if (!inGroup) {
        const gname = await getGroupName(botToken, GROUP_ID);
        await sendMessage(botToken, chatId, `⚠️ 当前用户无权限，只允许 ${gname} 群组内部人员使用。`);
        return;
      }
    }

    const cookie = await getCookie(apiUrl, username, password, KV);
    const t0 = Date.now();
    const cfgR = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/config`, {
      method: 'GET',
      headers: { 'Cookie': cookie, 'User-Agent': USER_AGENT }
    });
    const apiRespTime = Date.now() - t0;
    if (!cfgR.ok) throw new Error(`config HTTP ${cfgR.status}`);
    const cfgJ = await cfgR.json();
    const cfg = cfgJ.Config || {};
    const userCount = cfg.UserConfig?.Users?.length || 0;
    const sourceCount = cfg.SourceConfig?.length || 0;
    const liveCount = cfg.LiveConfig?.length || 0;
    const activeSourceCount = (cfg.SourceConfig || []).filter(s => !s.disabled).length || 0;
    const activeLiveCount = (cfg.LiveConfig || []).filter(l => !l.disabled).length || 0;
    const lastCheck = cfg.ConfigSubscribtion?.LastCheck;
    const lastUpdate = lastCheck ? new Date(lastCheck).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }) : '未知';
    // test moontv url
    let moontvResp = null;
    try {
      const t1 = Date.now();
      await fetch(moontvUrl, { method: 'GET', headers: { 'User-Agent': USER_AGENT } });
      moontvResp = Date.now() - t1;
    } catch (e) { moontvResp = null; }

    const siteNameFinal = siteName || cfg.SiteConfig?.SiteName || 'MoonTV';
    const msg = `🎬 <b>${siteNameFinal}</b> 站点状态

👥 总用户: <b>${userCount}</b>
🎞 视频源: <b>${activeSourceCount}</b>/<b>${sourceCount}</b>
📺 直播源: <b>${activeLiveCount}</b>/<b>${liveCount}</b>

🔄 配置更新时间: ${lastUpdate}
⚡ API 延迟: ${getLatencyStatus(apiRespTime)} ${apiRespTime}ms
🌐 站点访问: ${getLatencyStatus(moontvResp)} ${moontvResp !== null ? moontvResp + 'ms' : '未知'}

<i>最后更新: ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</i>`;
    await sendMessage(botToken, chatId, msg);
  } catch (e) {
    console.error('handleStateCommand error:', e);
    await sendMessage(botToken, chatId, `❌ 获取站点状态失败: ${e.message}`);
  }
}

/* --------------------- 群组检查（可选） --------------------- */

async function checkUserInGroup(botToken, groupId, userId) {
  if (!groupId) return true;
  try {
    const r = await fetch(`https://api.telegram.org/bot${botToken}/getChatMember`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: groupId, user_id: userId })
    });
    const j = await r.json();
    if (!j.ok) return false;
    const member = j.result;
    const status = member.status;
    const isStandard = ['creator', 'administrator', 'member'].includes(status);
    const isRestricted = status === 'restricted' && member.is_member === true;
    const isExcluded = ['left', 'kicked'].includes(status);
    return (isStandard || isRestricted) && !isExcluded;
  } catch (e) {
    console.error('checkUserInGroup error:', e);
    return false;
  }
}

async function getGroupName(botToken, groupId) {
  if (!groupId) return '指定群组';
  try {
    const r = await fetch(`https://api.telegram.org/bot${botToken}/getChat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: groupId })
    });
    const j = await r.json();
    return j.ok ? j.result.title || '指定群组' : '指定群组';
  } catch (e) {
    return '指定群组';
  }
}

/* --------------------- /chat 功能（两步） and 管理员回复 --------------------- */

async function handleChatSendToAdmin(botToken, fromUserId, content, adminId) {
  const messageToAdmin = `💬 用户(${fromUserId})发来消息：\n${content}`;
  await sendMessage(botToken, adminId, messageToAdmin);
}

/* 管理员回复转发（解析我们发出的消息） */
async function handleAdminReplyToUser(botToken, replyMessage) {
  if (!replyMessage.reply_to_message || !replyMessage.reply_to_message.text) return;
  const original = replyMessage.reply_to_message.text;
  const match = original.match(/用户\((\d+)\)/);
  if (!match) return;
  const targetUserId = match[1];
  const replyText = replyMessage.text || '';
  await sendMessage(botToken, targetUserId, `📩 管理员回复：\n${replyText}`);
}

/* --------------------- 主 Webhook 入口 --------------------- */

export default {
  async fetch(request, env, ctx) {
    // env variables
    const botToken = env.BOT_TOKEN;
    const ADMIN_ID = String(env.ADMIN_ID || '');
    const moontvUrl = extractBaseUrl(env.MOONTVURL || 'https://moontv.com/');
    const apiUrl = extractBaseUrl(env.APIURL || moontvUrl);
    const username = env.USERNAME || 'admin';
    const password = env.PASSWORD || 'admin_password';
    const GROUP_ID = env.GROUP_ID || '';
    const siteName = env.NEXT_PUBLIC_SITE_NAME || null;
    const KV = env.KV;

    if (request.method === 'GET') {
      // health check
      return new Response('OK');
    }

    if (request.method !== 'POST') return new Response('Not Found', { status: 404 });

    let update;
    try {
      update = await request.json();
    } catch (e) {
      console.error('invalid json body', e);
      return new Response('OK');
    }

    if (!update || !update.message) return new Response('OK');

    const message = update.message;
    const from = message.from || {};
    const userId = String(from.id);
    const chatId = message.chat?.id;
    const chatType = message.chat?.type || 'private';
    const text = (message.text || '').trim();

    try {
      // 如果是管理员发来的消息 -> 走管理员回复逻辑（在私聊中回复我们转发给他的消息即可）
      if (String(userId) === String(ADMIN_ID)) {
        await handleAdminReplyToUser(botToken, message);
        return new Response('OK');
      }

      // 1) 优先处理等待态：waiting_pwd, waiting_chat
      const waitingPwdKey = `user:${userId}:waiting_pwd`;
      const waitingChatKey = `user:${userId}:waiting_chat`;

      const waitingPwd = await KV.get(waitingPwdKey);
      if (waitingPwd === 'true') {
        const newPwd = text;
        // 验证密码格式：6-20 字母或数字
        if (!/^[A-Za-z0-9]{6,20}$/.test(newPwd)) {
          await sendMessage(botToken, userId, "❌ 密码格式不正确，请输入 6～20 位字母或数字：");
          return new Response('OK');
        }
        // 执行改密
        await handlePasswordCommand(botToken, Number(userId), chatId, chatType, GROUP_ID, newPwd, apiUrl, moontvUrl, username, password, KV, siteName);
        await KV.delete(waitingPwdKey);
        return new Response('OK');
      }

      const waitingChat = await KV.get(waitingChatKey);
      if (waitingChat === 'true') {
        const content = text;
        if (!content) {
          await sendMessage(botToken, userId, "⚠️ 内容不能为空，请重新输入：");
          return new Response('OK');
        }
        // 发送给管理员（私聊）
        await handleChatSendToAdmin(botToken, userId, content, ADMIN_ID);
        await sendMessage(botToken, userId, "📨 已将消息发送给管理员");
        await KV.delete(waitingChatKey);
        return new Response('OK');
      }

      // 2) 命令处理
      // /pwd：如果带参数则立即改密，否则进入等待输入
      if (text === '/pwd' || text.startsWith('/pwd ')) {
        if (text.trim() === '/pwd') {
          await KV.put(waitingPwdKey, 'true');
          await sendMessage(botToken, userId, "🔐 请输入新的密码（6～20 位字母或数字）：");
          return new Response('OK');
        } else {
          const newPwd = text.substring(5).trim();
          if (!/^[A-Za-z0-9]{6,20}$/.test(newPwd)) {
            await sendMessage(botToken, userId, "❌ 密码格式不正确，请使用 6～20 位字母或数字：");
            return new Response('OK');
          }
          await handlePasswordCommand(botToken, Number(userId), chatId, chatType, GROUP_ID, newPwd, apiUrl, moontvUrl, username, password, KV, siteName);
          return new Response('OK');
        }
      }

      // /chat：两步模式或单行发送
      if (text === '/chat' || text.startsWith('/chat ')) {
        if (text.trim() === '/chat') {
          await KV.put(waitingChatKey, 'true');
          await sendMessage(botToken, userId, "✏️ 请输入要发送给管理员的内容：");
          return new Response('OK');
        } else {
          const content = text.substring(5).trim();
          if (!content) {
            await sendMessage(botToken, userId, "✏️ 请在 /chat 后输入要发送给管理员的内容");
            return new Response('OK');
          }
          await handleChatSendToAdmin(botToken, userId, content, ADMIN_ID);
          await sendMessage(botToken, userId, "📨 已将消息发送给管理员");
          return new Response('OK');
        }
      }

      // /start
      if (text === '/start' || text.startsWith('/start ')) {
        await handleStartCommand(botToken, Number(userId), chatId, chatType, GROUP_ID, apiUrl, moontvUrl, username, password, KV, siteName);
        return new Response('OK');
      }

      // /state
      if (text === '/state' || text.startsWith('/state ')) {
        await handleStateCommand(botToken, Number(userId), chatId, GROUP_ID, apiUrl, moontvUrl, username, password, KV, siteName);
        return new Response('OK');
      }

      // 未匹配到命令 - 忽略或提示
      // await sendMessage(botToken, userId, "未识别的命令，可使用 /start /pwd /state /chat");
      return new Response('OK');
    } catch (e) {
      console.error('main handler error:', e);
      return new Response('Error', { status: 500 });
    }
  }
};
