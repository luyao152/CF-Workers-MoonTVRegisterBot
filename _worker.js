// MoonTV 双向聊天机器人 - Cloudflare Worker
// 完整功能版 - 零群组依赖

const USER_AGENT = "CF-Workers-MoonTVRegisterBot/cmliu";

// 生成初始密码
function generateInitialPassword(userId) {
    const timestamp = Date.now();
    const rawText = `${userId}${timestamp}`;
    return crypto.subtle.digest('MD5', new TextEncoder().encode(rawText))
        .then(hashBuffer => {
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('').substring(0, 8);
        });
}

// 提取基础域名URL
function extractBaseUrl(url) {
    try {
        const urlObj = new URL(url);
        return `${urlObj.protocol}//${urlObj.host}`;
    } catch (error) {
        console.error('URL解析失败:', error);
        return url;
    }
}

// 获取最新APP下载页信息
async function getLatestAppRelease() {
    try {
        const response = await fetch('https://api.github.com/repos/MoonTechLab/Selene/releases/latest', {
            headers: { 'User-Agent': USER_AGENT }
        });

        if (!response.ok) throw new Error(`GitHub API请求失败: HTTP ${response.status}`);
        const releaseData = await response.json();
        
        return {
            version: releaseData.tag_name,
            downloadUrl: releaseData.html_url
        };
    } catch (error) {
        console.error('获取最新APP版本失败:', error);
        return null;
    }
}

// 获取用户信息
async function getUserInfo(bot_token, userId) {
    try {
        const response = await fetch(`https://api.telegram.org/bot${bot_token}/getChat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: userId }),
        });

        const result = await response.json();
        if (result.ok) {
            const user = result.result;
            return {
                id: user.id,
                firstName: user.first_name || '',
                lastName: user.last_name || '',
                username: user.username || '无'
            };
        }
        return null;
    } catch (error) {
        console.error('Error getting user info:', error);
        return null;
    }
}

// 获取管理员列表
async function getAdminUsers(KV) {
    try {
        const adminUsersData = await KV.get('admin_users');
        return adminUsersData ? JSON.parse(adminUsersData) : [];
    } catch (error) {
        console.error('Error getting admin users:', error);
        return [];
    }
}

// 添加管理员
async function addAdminUser(KV, userId) {
    try {
        const adminUsers = await getAdminUsers(KV);
        if (!adminUsers.includes(userId.toString())) {
            adminUsers.push(userId.toString());
            await KV.put('admin_users', JSON.stringify(adminUsers));
        }
        return true;
    } catch (error) {
        console.error('Error adding admin user:', error);
        return false;
    }
}

// 检查用户是否是管理员
async function isAdmin(userId, KV) {
    const adminUsers = await getAdminUsers(KV);
    return adminUsers.length === 0 || adminUsers.includes(userId.toString());
}

// 处理用户消息
async function handleUserMessage(bot_token, userId, chatId, text, KV) {
    try {
        const userInfo = await getUserInfo(bot_token, userId);
        const userName = userInfo ? 
            (userInfo.username !== '无' ? `@${userInfo.username}` : `${userInfo.firstName} ${userInfo.lastName}`.trim()) : 
            `用户${userId}`;

        // 存储用户消息
        const messageId = Date.now().toString();
        const messageData = {
            userId: userId,
            userName: userName,
            message: text,
            timestamp: new Date().toISOString(),
            type: 'user_to_admin'
        };
        await KV.put(`chat:${messageId}`, JSON.stringify(messageData), { expirationTtl: 86400 });

        // 通知管理员
        await notifyAdminsNewMessage(bot_token, userId, userName, text, KV);

        await sendMessage(bot_token, chatId, "✅ 您的消息已发送给管理员，我们会尽快回复您。");

    } catch (error) {
        console.error('Error handling user message:', error);
        await sendMessage(bot_token, chatId, "❌ 发送消息失败，请稍后再试。");
    }
}

// 通知管理员有新消息
async function notifyAdminsNewMessage(bot_token, userId, userName, message, KV) {
    try {
        const adminUsers = await getAdminUsers(KV);
        if (adminUsers.length === 0) {
            // 如果没有管理员，自动将第一个接收消息的用户设为管理员
            await addAdminUser(KV, userId);
            return;
        }

        const adminMessage = `💬 <b>新用户消息</b>\n\n👤 <b>发件人：</b>${userName} (ID: ${userId})\n📝 <b>消息内容：</b>\n<code>${message}</code>\n\n⏰ <b>时间：</b>${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n\n💡 回复此用户请点击下方按钮`;

        const inlineKeyboard = [[{ text: "💬 回复此用户", callback_data: `admin_reply_${userId}` }]];

        // 发送给每个管理员
        for (const adminId of adminUsers) {
            try {
                await sendInlineKeyboard(bot_token, adminId, adminMessage, inlineKeyboard);
            } catch (error) {
                console.error(`无法发送消息给管理员 ${adminId}:`, error);
            }
        }
    } catch (error) {
        console.error('Error notifying admins:', error);
    }
}

// 处理管理员回复
async function handleAdminReply(bot_token, adminId, targetUserId, KV) {
    try {
        await KV.put(`admin_reply:${adminId}`, JSON.stringify({
            targetUserId: targetUserId,
            timestamp: Date.now()
        }), { expirationTtl: 300 });

        const userInfo = await getUserInfo(bot_token, targetUserId);
        const userName = userInfo ? 
            (userInfo.username !== '无' ? `@${userInfo.username}` : `${userInfo.firstName} ${userInfo.lastName}`.trim()) : 
            `用户${targetUserId}`;

        const message = `💬 <b>回复用户</b>\n\n👤 <b>收件人：</b>${userName} (ID: ${targetUserId})\n\n📝 请输入回复内容：\n\n⏰ 请在5分钟内完成\n❌ 输入 /cancel 取消`;
        await sendMessage(bot_token, adminId, message);

    } catch (error) {
        console.error('Error handling admin reply:', error);
        await sendMessage(bot_token, adminId, "❌ 操作失败，请稍后再试。");
    }
}

// 处理管理员回复输入
async function handleAdminReplyInput(bot_token, adminId, chatId, text, KV) {
    try {
        const replyData = await KV.get(`admin_reply:${adminId}`);
        if (!replyData) {
            await sendMessage(bot_token, chatId, "❌ 回复会话已过期，请重新选择用户。");
            return;
        }

        const replyInfo = JSON.parse(replyData);
        const targetUserId = replyInfo.targetUserId;
        await KV.delete(`admin_reply:${adminId}`);

        const adminInfo = await getUserInfo(bot_token, adminId);
        const adminName = adminInfo ? 
            (adminInfo.username !== '无' ? `@${adminInfo.username}` : `${adminInfo.firstName} ${adminInfo.lastName}`.trim()) : 
            `管理员`;

        // 存储管理员回复
        const messageId = `admin_${Date.now()}`;
        const messageData = {
            adminId: adminId,
            adminName: adminName,
            targetUserId: targetUserId,
            message: text,
            timestamp: new Date().toISOString(),
            type: 'admin_to_user'
        };
        await KV.put(`chat:${messageId}`, JSON.stringify(messageData), { expirationTtl: 86400 });

        // 发送回复给用户
        const userMessage = `💌 <b>管理员回复</b>\n\n👤 <b>来自：</b>${adminName}\n📝 <b>回复内容：</b>\n<code>${text}</code>\n\n⏰ <b>时间：</b>${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n\n💡 如需继续沟通，请直接发送消息。`;
        await sendMessage(bot_token, targetUserId, userMessage);

        await sendMessage(bot_token, chatId, `✅ 回复已发送给用户`);

    } catch (error) {
        console.error('Error handling admin reply input:', error);
        await sendMessage(bot_token, chatId, "❌ 发送回复失败，请稍后再试。");
    }
}

// 进入聊天模式
async function handleChatMode(bot_token, userId, chatId, KV) {
    try {
        await KV.put(`chat_mode:${userId}`, 'true', { expirationTtl: 1800 });
        await sendMessage(bot_token, chatId, `💬 <b>聊天模式已开启</b>\n\n📝 您现在可以直接发送消息与管理员沟通\n⏰ 聊天模式将持续30分钟\n❌ 输入 <code>/end</code> 退出聊天模式\n\n💡 请直接发送您的消息，我们会尽快回复您。`);
    } catch (error) {
        console.error('Error starting chat mode:', error);
        await sendMessage(bot_token, chatId, "❌ 开启聊天模式失败，请稍后再试。");
    }
}

// 退出聊天模式
async function handleEndChatMode(bot_token, userId, chatId, KV) {
    try {
        await KV.delete(`chat_mode:${userId}`);
        await sendMessage(bot_token, chatId, "❌ 聊天模式已结束。\n\n💡 如需再次联系管理员，请输入 <code>/chat</code> 重新开启聊天模式。");
    } catch (error) {
        console.error('Error ending chat mode:', error);
        await sendMessage(bot_token, chatId, "❌ 操作失败，请稍后再试。");
    }
}

// 管理员面板
async function handleAdminPanel(bot_token, adminId, chatId, KV) {
    try {
        const message = "👑 <b>管理员控制面板</b>\n\n💡 请选择要执行的操作：";
        const inlineKeyboard = [
            [{ text: "📋 最近消息", callback_data: "admin_recent_messages" }],
            [{ text: "⚙️ 系统设置", callback_data: "admin_system_settings" }],
            [{ text: "📊 系统状态", callback_data: "admin_system_status" }]
        ];
        await sendInlineKeyboard(bot_token, chatId, message, inlineKeyboard);
    } catch (error) {
        console.error('Error handling admin panel:', error);
        await sendMessage(bot_token, chatId, "❌ 加载管理员面板失败。");
    }
}

// 发送带内联键盘的消息
async function sendInlineKeyboard(bot_token, chatId, text, inlineKeyboard) {
    try {
        const messageData = {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML',
            reply_markup: { inline_keyboard: inlineKeyboard }
        };
        await fetch(`https://api.telegram.org/bot${bot_token}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
            body: JSON.stringify(messageData)
        });
    } catch (error) {
        console.error('Error sending inline keyboard:', error);
    }
}

// 发送普通消息
async function sendMessage(bot_token, chatId, text, moontvUrl = null, siteName = null, appInfo = null) {
    try {
        const messageData = {
            chat_id: chatId,
            text: text,
            parse_mode: 'HTML'
        };

        const inlineKeyboard = [];
        if (moontvUrl && siteName) {
            inlineKeyboard.push([{ text: `🎬 ${siteName}在线观影`, url: moontvUrl }]);
        }
        if (appInfo && appInfo.downloadUrl) {
            const buttonText = appInfo.version ? `📱 APP下载 ${appInfo.version}` : '📱 APP客户端下载';
            inlineKeyboard.push([{ text: buttonText, url: appInfo.downloadUrl }]);
        }
        if (inlineKeyboard.length > 0) {
            messageData.reply_markup = { inline_keyboard: inlineKeyboard };
        }

        await fetch(`https://api.telegram.org/bot${bot_token}/sendMessage`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
            body: JSON.stringify(messageData)
        });
    } catch (error) {
        console.error('Error sending message:', error);
    }
}

// 获取Cookie函数
async function getCookie(apiUrl, username, password, KV) {
    try {
        let cookieData = await KV.get('cookie');
        if (cookieData) {
            try {
                const cookieObject = JSON.parse(cookieData);
                const currentTime = Date.now();
                const cookieTime = cookieObject.timestamp;
                if (currentTime - cookieTime < 432000000) {
                    const encodedCookie = encodeURIComponent(encodeURIComponent(cookieData));
                    return `auth=${encodedCookie}`;
                }
            } catch (parseError) {
                console.log('Cookie解析失败，将重新获取:', parseError.message);
            }
        }

        console.log('正在获取新的Cookie...');
        const loginResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
            body: JSON.stringify({ username: username, password: password })
        });

        if (!loginResponse.ok) throw new Error(`登录请求失败: ${loginResponse.status}`);
        const loginResult = await loginResponse.json();
        if (!loginResult.ok) throw new Error('登录失败: 用户名或密码错误');

        const setCookieHeader = loginResponse.headers.get('set-cookie');
        if (!setCookieHeader) throw new Error('未收到Cookie响应');

        const authCookieMatch = setCookieHeader.match(/auth=([^;]+)/);
        if (!authCookieMatch) throw new Error('未找到auth cookie');

        const encodedCookieValue = authCookieMatch[1];
        const decodedOnce = decodeURIComponent(encodedCookieValue);
        const decodedTwice = decodeURIComponent(decodedOnce);

        await KV.put('cookie', decodedTwice);
        const finalEncodedCookie = encodeURIComponent(encodeURIComponent(decodedTwice));
        return `auth=${finalEncodedCookie}`;

    } catch (error) {
        console.error('获取Cookie失败:', error);
        throw error;
    }
}

// 检查用户是否已注册
async function checkUserExists(apiUrl, username, password, KV, targetUsername) {
    try {
        const cookie = await getCookie(apiUrl, username, password, KV);
        const configResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/config`, {
            method: 'GET',
            headers: { 'Cookie': cookie, 'User-Agent': USER_AGENT }
        });

        if (!configResponse.ok) throw new Error(`获取配置API失败: HTTP ${configResponse.status}`);
        const configResult = await configResponse.json();

        if (!configResult.Config || !configResult.Config.UserConfig || !configResult.Config.UserConfig.Users) {
            return false;
        }

        return configResult.Config.UserConfig.Users.some(user => user.username === targetUsername);
    } catch (error) {
        console.error('检查用户是否存在失败:', error);
        return false;
    }
}

// 注册用户
async function registerUser(apiUrl, username, password, KV, targetUsername, targetPassword) {
    try {
        const cookie = await getCookie(apiUrl, username, password, KV);
        const addUserResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': cookie, 'User-Agent': USER_AGENT },
            body: JSON.stringify({
                targetUsername: targetUsername,
                targetPassword: targetPassword,
                action: 'add'
            })
        });

        if (!addUserResponse.ok) throw new Error(`添加用户API失败: HTTP ${addUserResponse.status}`);
        const addResult = await addUserResponse.json();
        return addResult.ok;
    } catch (error) {
        console.error('Error registering user:', error);
        return false;
    }
}

// 修改密码
async function changeUserPassword(bot_token, userId, chatId, newPassword, apiUrl, moontvUrl, username, password, KV) {
    try {
        if (!newPassword || newPassword.length < 6) {
            await sendMessage(bot_token, chatId, "❌ 密码长度至少6位");
            return new Response('OK');
        }

        const userExists = await checkUserExists(apiUrl, username, password, KV, userId.toString());
        if (!userExists) {
            await sendMessage(bot_token, chatId, "❌ 用户未注册，请先使用 /start 注册");
            return new Response('OK');
        }

        const cookie = await getCookie(apiUrl, username, password, KV);
        const changePasswordResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Cookie': cookie, 'User-Agent': USER_AGENT },
            body: JSON.stringify({
                targetUsername: userId.toString(),
                targetPassword: newPassword,
                action: 'changePassword'
            })
        });

        if (!changePasswordResponse.ok) throw new Error(`修改密码API失败: HTTP ${changePasswordResponse.status}`);
        const changeResult = await changePasswordResponse.json();
        if (!changeResult.ok) throw new Error('修改密码失败');

        await sendMessage(bot_token, chatId, `✅ 密码修改成功！\n\n🔑 <b>新密码：</b><code>${newPassword}</code>\n\n💡 请妥善保存新密码`);
        return new Response('OK');
    } catch (error) {
        console.error('Error changing password:', error);
        await sendMessage(bot_token, chatId, "❌ 密码修改失败，请稍后再试。");
        return new Response('OK');
    }
}

// 处理 /start 命令
async function handleStartCommand(bot_token, userId, chatId, apiUrl, moontvUrl, username, password, KV, siteName) {
    try {
        let actualSiteName = siteName;
        if (!actualSiteName) {
            try {
                const cookie = await getCookie(apiUrl, username, password, KV);
                const configResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/config`, {
                    method: 'GET',
                    headers: { 'Cookie': cookie, 'User-Agent': USER_AGENT }
                });

                if (configResponse.ok) {
                    const configResult = await configResponse.json();
                    actualSiteName = configResult.Config?.SiteConfig?.SiteName || 'MoonTV';
                }
            } catch (error) {
                actualSiteName = 'MoonTV';
            }
        }

        const userExists = await checkUserExists(apiUrl, username, password, KV, userId.toString());
        const appInfo = await getLatestAppRelease();

        let responseMessage;
        if (!userExists) {
            const initialPassword = await generateInitialPassword(userId);
            await sendMessage(bot_token, chatId, "⏳ 正在为您注册账户，请稍等...", moontvUrl, actualSiteName);

            const registrationSuccess = await registerUser(apiUrl, username, password, KV, userId.toString(), initialPassword);
            if (registrationSuccess) {
                responseMessage = `✅ 注册成功！\n\n🌐 <b>服务器：</b><code>${moontvUrl}</code>\n🆔 <b>用户名：</b><code>${userId}</code>\n🔑 <b>访问密码：</b><code>${initialPassword}</code>\n\n💡 使用 <code>/pwd</code> 修改密码\n💬 使用 <code>/chat</code> 联系管理员`;
            } else {
                await sendMessage(bot_token, chatId, "❌ 注册失败，请稍后再试或联系管理员。", moontvUrl, actualSiteName, appInfo);
                return new Response('OK');
            }
        } else {
            responseMessage = `ℹ️ 您已注册过账户\n\n🌐 <b>服务器：</b><code>${moontvUrl}</code>\n🆔 <b>用户名：</b><code>${userId}</code>\n\n💡 使用 <code>/pwd</code> 修改密码\n💬 使用 <code>/chat</code> 联系管理员`;
        }

        await sendMessage(bot_token, chatId, responseMessage, moontvUrl, actualSiteName, appInfo);
        return new Response('OK');
    } catch (error) {
        console.error('Error in start command:', error);
        await sendMessage(bot_token, chatId, "❌ 操作失败，请稍后再试。");
        return new Response('OK');
    }
}

// 处理 /pwd 命令
async function handlePwdCommand(bot_token, userId, chatId, text, apiUrl, moontvUrl, username, password, KV, siteName) {
    try {
        if (text === '/pwd' || text.trim() === '/pwd') {
            await KV.put(`pwd_waiting:${userId}`, 'true', { expirationTtl: 300 });
            await sendMessage(bot_token, chatId, "🔐 <b>密码修改</b>\n\n请输入新密码（至少6位）：\n\n⏰ 请在5分钟内完成\n❌ 输入 /cancel 取消");
            return new Response('OK');
        } else if (text.startsWith('/pwd ')) {
            const newPassword = text.substring(5).trim();
            return await changeUserPassword(bot_token, userId, chatId, newPassword, apiUrl, moontvUrl, username, password, KV);
        }
    } catch (error) {
        console.error('Error in pwd command:', error);
        await sendMessage(bot_token, chatId, "❌ 操作失败，请稍后再试。");
        return new Response('OK');
    }
}

// 处理密码输入
async function handlePasswordInput(bot_token, userId, chatId, newPassword, apiUrl, moontvUrl, username, password, KV, siteName) {
    await KV.delete(`pwd_waiting:${userId}`);
    return await changeUserPassword(bot_token, userId, chatId, newPassword, apiUrl, moontvUrl, username, password, KV);
}

// 处理取消命令
async function handleCancelCommand(bot_token, userId, chatId, isWaitingForPassword, isAdminWaitingReply, KV) {
    if (isWaitingForPassword) {
        await KV.delete(`pwd_waiting:${userId}`);
        await sendMessage(bot_token, chatId, "❌ 密码修改操作已取消");
    } else if (isAdminWaitingReply) {
        await KV.delete(`admin_reply:${userId}`);
        await sendMessage(bot_token, chatId, "❌ 回复操作已取消");
    } else {
        await sendMessage(bot_token, chatId, "ℹ️ 没有需要取消的操作");
    }
    return new Response('OK');
}

// 处理回调查询
async function handleCallbackQuery(bot_token, callbackQuery, KV) {
    try {
        const userId = callbackQuery.from.id;
        const chatId = callbackQuery.message.chat.id;
        const data = callbackQuery.data;

        await fetch(`https://api.telegram.org/bot${bot_token}/answerCallbackQuery`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ callback_query_id: callbackQuery.id })
        });

        if (data.startsWith('admin_reply_')) {
            const targetUserId = data.split('_')[2];
            return await handleAdminReply(bot_token, userId, targetUserId, KV);
        } else if (data === 'admin_panel') {
            return await handleAdminPanel(bot_token, userId, chatId, KV);
        } else if (data === 'admin_system_status') {
            await sendMessage(bot_token, chatId, "📊 系统状态功能正在开发中...");
        } else if (data === 'admin_recent_messages') {
            await sendMessage(bot_token, chatId, "📋 最近消息功能正在开发中...");
        } else if (data === 'admin_system_settings') {
            await sendMessage(bot_token, chatId, "⚙️ 系统设置功能正在开发中...");
        }
    } catch (error) {
        console.error('Error handling callback query:', error);
    }
    return new Response('OK');
}

// 处理检测端点
async function handleCheckEndpoint(apiUrl, username, password, KV) {
    const checkResult = {
        timestamp: new Date().toISOString(),
        moontvApi: { url: apiUrl, status: 'unknown', error: null, responseTime: null },
        cookieStatus: { exists: false, valid: false, error: null },
        configApi: { accessible: false, userCount: 0, error: null },
        errors: []
    };

    let startTime = Date.now();
    try {
        const loginResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'User-Agent': USER_AGENT },
            body: JSON.stringify({ username: username, password: password })
        });

        checkResult.moontvApi.responseTime = Date.now() - startTime;
        if (!loginResponse.ok) {
            checkResult.moontvApi.status = 'error';
            checkResult.moontvApi.error = `API请求失败: HTTP ${loginResponse.status}`;
            checkResult.errors.push(`MoonTV API连接失败: HTTP ${loginResponse.status}`);
        } else {
            const loginResult = await loginResponse.json();
            if (loginResult.ok) {
                checkResult.moontvApi.status = 'connected';
                try {
                    const cookie = await getCookie(apiUrl, username, password, KV);
                    checkResult.cookieStatus.exists = true;
                    checkResult.cookieStatus.valid = true;
                    
                    const configResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/config`, {
                        method: 'GET',
                        headers: { 'Cookie': cookie, 'User-Agent': USER_AGENT }
                    });

                    if (configResponse.ok) {
                        const configResult = await configResponse.json();
                        checkResult.configApi.accessible = true;
                        if (configResult.Config && configResult.Config.UserConfig && configResult.Config.UserConfig.Users) {
                            checkResult.configApi.userCount = configResult.Config.UserConfig.Users.length;
                        }
                    } else {
                        checkResult.configApi.error = `配置API访问失败: HTTP ${configResponse.status}`;
                        checkResult.errors.push(checkResult.configApi.error);
                    }
                } catch (cookieError) {
                    checkResult.cookieStatus.error = cookieError.message;
                    checkResult.errors.push(`Cookie获取失败: ${cookieError.message}`);
                }
            } else {
                checkResult.moontvApi.status = 'auth_error';
                checkResult.moontvApi.error = '登录认证失败';
                checkResult.errors.push('用户名或密码错误');
            }
        }
    } catch (networkError) {
        checkResult.moontvApi.status = 'network_error';
        checkResult.moontvApi.responseTime = Date.now() - startTime;
        checkResult.moontvApi.error = networkError.message;
        checkResult.errors.push(`网络错误: ${networkError.message}`);
    }

    return new Response(JSON.stringify(checkResult, null, 2), {
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-cache' },
    });
}

// 初始化 Webhook
async function handleWebhookInit(bot_token, workerUrl, token) {
    try {
        const webhookUrl = workerUrl.replace(`/${token}`, '');
        const setWebhookResponse = await fetch(`https://api.telegram.org/bot${bot_token}/setWebhook`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: webhookUrl }),
        });

        const setWebhookResult = await setWebhookResponse.json();
        const setCommandsResponse = await fetch(`https://api.telegram.org/bot${bot_token}/setMyCommands`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                commands: [
                    { command: "start", description: "注册/查看用户信息" },
                    { command: "pwd", description: "修改密码" },
                    { command: "chat", description: "联系管理员" },
                    { command: "state", description: "查看站点状态" },
                    { command: "admin", description: "管理员面板" }
                ]
            }),
        });
        const setCommandsResult = await setCommandsResponse.json();

        return new Response(JSON.stringify({
            webhook: setWebhookResult,
            commands: setCommandsResult,
            message: "Bot initialized successfully"
        }, null, 2), { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        return new Response(JSON.stringify({
            error: "Failed to initialize bot",
            message: error.message
        }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

// 处理 /state 命令
async function handleStateCommand(bot_token, userId, chatId, apiUrl, moontvUrl, username, password, KV, siteName) {
    try {
        const cookie = await getCookie(apiUrl, username, password, KV);
        const apiStartTime = Date.now();
        const configResponse = await fetch(`${apiUrl.replace(/\/$/, '')}/api/admin/config`, {
            method: 'GET',
            headers: { 'Cookie': cookie, 'User-Agent': USER_AGENT }
        });

        if (!configResponse.ok) throw new Error(`配置API访问失败: HTTP ${configResponse.status}`);
        const configResult = await configResponse.json();
        const apiResponseTime = Date.now() - apiStartTime;

        if (!configResult.Config) throw new Error('配置数据获取失败');

        const userCount = configResult.Config.UserConfig?.Users?.length || 0;
        const sourceCount = configResult.Config.SourceConfig?.length || 0;
        const liveCount = configResult.Config.LiveConfig?.length || 0;
        const configSiteName = siteName || configResult.Config.SiteConfig?.SiteName || 'MoonTV';

        const activeSourceCount = configResult.Config.SourceConfig?.filter(source => !source.disabled).length || 0;
        const activeLiveCount = configResult.Config.LiveConfig?.filter(live => !live.disabled).length || 0;

        const lastCheck = configResult.Config.ConfigSubscribtion?.LastCheck;
        const lastUpdateTime = lastCheck ? new Date(lastCheck).toLocaleString('zh-CN', {
            timeZone: 'Asia/Shanghai',
            year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
        }) : '未知';

        let moontvResponseTime = null;
        try {
            const moontvStartTime = Date.now();
            await fetch(moontvUrl, { method: 'GET', headers: { 'User-Agent': USER_AGENT } });
            moontvResponseTime = Date.now() - moontvStartTime;
        } catch (error) {
            console.error('测试 moontvUrl 延迟失败:', error);
        }

        const getLatencyStatus = (responseTime) => {
            if (!responseTime) return '未知';
            if (responseTime < 300) return '良好';
            if (responseTime < 1000) return '一般';
            return '拥挤';
        };

        const stateMessage = `🎬 <b>${configSiteName}</b> 站点状态

📊 <b>核心统计</b>
👥 总用户数: <b>${userCount}</b> 人
🎞️ 视 频 源: <b>${activeSourceCount}</b>/<b>${sourceCount}</b> 个
📺 直 播 源: <b>${activeLiveCount}</b>/<b>${liveCount}</b> 个

⚙️ <b>系统信息</b>
🔄 配置更新: ${lastUpdateTime}
🎯 自动更新: ${configResult.Config.ConfigSubscribtion?.AutoUpdate ? '✅ 已启用' : '❌ 已禁用'}

📈 <b>服务质量</b>
⚡ API状态: <b>${getLatencyStatus(apiResponseTime)}</b> ${apiResponseTime}ms
🌐 访问状态: <b>${getLatencyStatus(moontvResponseTime)}</b> ${moontvResponseTime !== null ? moontvResponseTime + 'ms' : '未知'}

<i>最后更新: ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}</i>`;

        await sendMessage(bot_token, chatId, stateMessage, moontvUrl, configSiteName);
        return new Response('OK');
    } catch (apiError) {
        console.error('获取站点状态失败:', apiError);
        await sendMessage(bot_token, chatId, `❌ 获取站点状态失败: ${apiError.message}\n\n请稍后再试或联系管理员。`);
        return new Response('OK');
    }
}

// 主函数
export default {
    async fetch(request, env, ctx) {
        const moontvUrl = extractBaseUrl(env.MOONTVURL || "https://moontv.com/");
        const apiUrl = extractBaseUrl(env.APIURL || moontvUrl);
        const username = env.USERNAME || "admin";
        const password = env.PASSWORD || "admin_password";
        const token = env.TOKEN || "token";
        const bot_token = env.BOT_TOKEN || "8226743743:AAHfrc09vW8cxKHyU0q0YKPuCXrW1ICWdU0";
        const siteName = env.NEXT_PUBLIC_SITE_NAME || null;
        
        const url = new URL(request.url);
        const path = url.pathname;

        // 检查必需的环境变量
        const requiredEnvVars = ['BOT_TOKEN', 'MOONTVURL', 'USERNAME', 'PASSWORD', 'TOKEN'];
        for (const envVar of requiredEnvVars) {
            if (!env[envVar]) {
                return new Response(`错误: 缺少必需的环境变量 ${envVar}`, { status: 500 });
            }
        }

        // 处理 Webhook 初始化路径
        if (path.includes(`/${token}`)) {
            return await handleWebhookInit(bot_token, request.url, token);
        }

        // 处理检测路径
        if (path === '/check' && request.method === 'GET') {
            const urlParams = new URLSearchParams(url.search);
            const checkToken = urlParams.get('token');
            if (checkToken === token) {
                return await handleCheckEndpoint(apiUrl, username, password, env.KV);
            } else {
                return new Response("Forbidden", { status: 403 });
            }
        }

        // 处理 Telegram Webhook
        if (request.method === 'POST') {
            return await handleTelegramWebhook(request, bot_token, apiUrl, moontvUrl, username, password, env.KV, siteName);
        }

        return new Response("Not Found", { status: 404 });
    },
};

// 处理 Telegram Webhook
async function handleTelegramWebhook(request, bot_token, apiUrl, moontvUrl, username, password, KV, siteName) {
    try {
        const update = await request.json();

        // 处理回调查询（按钮点击）
        if (update.callback_query) {
            return await handleCallbackQuery(bot_token, update.callback_query, KV);
        }

        if (update.message && update.message.text) {
            const message = update.message;
            const userId = message.from.id;
            const chatId = message.chat.id;
            const text = message.text;
            const chatType = message.chat.type;

            // 只在私聊中处理消息
            if (chatType !== 'private') {
                if (text.startsWith('/')) {
                    await sendMessage(bot_token, chatId, "🔐 请私聊机器人使用功能\n\n💬 点击我的用户名进入私聊");
                }
                return new Response('OK');
            }

            const normalizedText = text.trim();

            // 检查用户状态
            const isWaitingForPassword = await KV.get(`pwd_waiting:${userId}`);
            const isInChatMode = await KV.get(`chat_mode:${userId}`);
            const isAdminWaitingReply = await KV.get(`admin_reply:${userId}`);

            // 处理普通消息（非命令）
            if (!normalizedText.startsWith('/') && normalizedText.length > 0) {
                if (isWaitingForPassword) {
                    return await handlePasswordInput(bot_token, userId, chatId, normalizedText, apiUrl, moontvUrl, username, password, KV, siteName);
                }
                if (isAdminWaitingReply) {
                    return await handleAdminReplyInput(bot_token, userId, chatId, normalizedText, KV);
                }
                if (isInChatMode) {
                    return await handleUserMessage(bot_token, userId, chatId, normalizedText, KV);
                }
                return new Response('OK');
            }

            // 处理命令
            if (normalizedText === '/start') {
                return await handleStartCommand(bot_token, userId, chatId, apiUrl, moontvUrl, username, password, KV, siteName);
            } else if (normalizedText.startsWith('/pwd')) {
                return await handlePwdCommand(bot_token, userId, chatId, normalizedText, apiUrl, moontvUrl, username, password, KV, siteName);
            } else if (normalizedText === '/state') {
                return await handleStateCommand(bot_token, userId, chatId, apiUrl, moontvUrl, username, password, KV, siteName);
            } else if (normalizedText === '/chat') {
                return await handleChatMode(bot_token, userId, chatId, KV);
            } else if (normalizedText === '/end') {
                return await handleEndChatMode(bot_token, userId, chatId, KV);
            } else if (normalizedText === '/admin') {
                return await handleAdminPanel(bot_token, userId, chatId, KV);
            } else if (normalizedText === '/cancel') {
                return await handleCancelCommand(bot_token, userId, chatId, isWaitingForPassword, isAdminWaitingReply, KV);
            }
        }

        return new Response('OK');
    } catch (error) {
        console.error('Error handling webhook:', error);
        return new Response('Error', { status: 500 });
    }
          }
