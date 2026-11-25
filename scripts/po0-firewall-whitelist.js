/*
 * po0 防火墙自动加白
 * 兼容：Surge / Stash / Shadowrocket / Loon / Quantumult X
 * （Egern 运行模型不同，用独立的 egern/po0-firewall-whitelist.js）
 *
 * cron / 网络事件 / 面板手动刷新：POST /api/firewall/<token>/add，
 * 面板自动刷新：GET /api/firewall/<token>，只查询状态，不写入白名单。
 * 面板手动刷新每次都加白，并依次显示各台机器的白名单明细，然后回到简要状态。
 * POST 把"当前请求源 IP"加入白名单，并回显
 *   {enabled, whitelist:[{ip,slot}], limit, currentIp}。token 走 URL 路径，无需
 *   Authorization 头。服务端对已在白名单的 IP 做幂等处理（重复请求不
 *   重复占坑、不推进淘汰队列），因此写入触发可直接请求。
 * 加白粒度为 C 段（/24）：服务端把 whitelist 条目和 currentIp 都归一化成
 *   x.x.x.0/24 回显；同段内换 IP 不产生新写入。脚本用 sameC24() 做匹配，
 *   兼容精确 IP 与 /24 段混杂的新旧格式。
 * 白名单写满后按写入时间先进先出自动淘汰最旧 IP；API 无删除接口。
 *
 * 策略：
 * - cron、网络事件和面板手动刷新直接 POST 上报当前出口 IP，蜂窝与 WiFi/有线同等处理。
 * - Surge 面板自动刷新只 GET 查询，不加白，也不弹系统通知。
 * - 默认 slotless 写入：按 updated_at 触发 LRU 淘汰，被挤出的设备靠自己的
 *   cron/事件几分钟内自动补回。
 * - 可选固定槽位：token 后加 @N（如 pgnfw_xxx@0）→ POST .../add?slot=N，
 *   把本机 IP 钉在槽位 N，**永不被 LRU 淘汰**。槽位写入语义：
 *     · 本机 IP 已在该槽位 → 刷新 updated_at；
 *     · 槽位有旧 IP → 行级顶替，旧 IP 丢弃；
 *     · 本机 IP 已 slotless → 删 slotless 行升级到该槽位；
 *     · 本机 IP 已占用**别的**槽位 → 403 冲突，需先去 UI 删旧槽位（脚本会报 ❌）。
 * - 蜂窝（主接口 pdp_ip*）写入的 IP 仅做 📶 标记，便于面板识别。
 *
 * token 来源（优先级从高到低）：
 * 1. argument: tokens=<pgnfw_xxx>[@槽位],<pgnfw_yyy>（Surge/Loon/Stash 模块参数）
 * 2. 持久化存储 key "po0fw_tokens"（Quantumult X 等不支持参数的客户端，
 *    可用 BoxJs 或一次性脚本写入）
 * 3. 下面的 INLINE_TOKENS 常量（自己维护脚本副本时直接填这里）
 */

var INLINE_TOKENS = "";

var API_BASE = "https://124.221.69.228/api/firewall/"; // + <token> [+ "/add"]
var STORE_PREFIX = "po0_fw_";
var TOKENS_KEY = "po0fw_tokens";
var PANEL_DETAIL_KEY = STORE_PREFIX + "panel_detail";
var PANEL_TITLE = "po0 防火墙";
var PANEL_DETAIL_PAGE_SIZE = 5;
var HIST_WINDOW_MS = 24 * 3600 * 1000; // 📶 标记的记账窗口

/* ---------- 环境兼容层 ---------- */

var isQX = typeof $task !== "undefined";
var isSurgeLike = typeof $httpClient !== "undefined"; // Surge/Stash/Shadowrocket/Loon

// 客户端细分：各家注入的标识不同，Loon 有全局 $loon，
// Surge 系则在 $environment 里带 surge-version / shadowrocket-version 等字段。
var envInfo = "";
try {
  if (typeof $environment !== "undefined" && $environment) {
    envInfo = JSON.stringify($environment).toLowerCase();
  }
} catch (e) {}

var isLoon = typeof $loon !== "undefined" || envInfo.indexOf("loon") >= 0;
var isPanel =
  typeof $input !== "undefined" && $input && $input.purpose === "panel";
var isAutoPanel =
  isPanel && typeof $trigger !== "undefined" && $trigger === "auto-interval";
var isSurgeFamily =
  envInfo.indexOf("surge-version") >= 0 ||
  envInfo.indexOf("shadowrocket") >= 0 ||
  envInfo.indexOf("stash") >= 0;

// ⚠️ timeout 单位在不同客户端不一致：
//   Surge / Shadowrocket / Stash → 秒
//   Loon / Quantumult X          → 毫秒
// 写死 15 会让 Loon 只等 15 毫秒 → 必然超时 → 回调 error=null → 通知里显示 "(null)"。
// 无法判定时干脆不传 timeout，交给模块声明的 timeout=60 兜底，避免再踩单位坑。
var REQUEST_TIMEOUT = null;
if (isLoon || isQX) REQUEST_TIMEOUT = 15000;
else if (isSurgeFamily) REQUEST_TIMEOUT = 15;

function storeRead(key) {
  if (isQX) return $prefs.valueForKey(key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.read(key);
  return null;
}

function storeWrite(value, key) {
  if (isQX) return $prefs.setValueForKey(value, key);
  if (typeof $persistentStore !== "undefined") return $persistentStore.write(value, key);
  return false;
}

function notify(title, subtitle, body) {
  if (isQX) $notify(title, subtitle, body);
  else if (typeof $notification !== "undefined") $notification.post(title, subtitle, body);
}

// 各客户端失败时回传的 error 五花八门：Loon 在网络瞬断 / TLS 握手失败时
// 直接回调 error=null，裸 String(null) 只会得到毫无信息量的 "null"。
function describeHttpError(error) {
  var text;
  if (error === null || error === undefined) text = "";
  else if (typeof error === "object")
    text = String(error.message || error.error || error.description || "");
  else text = String(error);
  text = text.replace(/^\s+|\s+$/g, "");
  if (text === "" || text === "null" || text === "undefined" || text === "{}") {
    return "网络请求失败（超时 / 握手失败 / 被拦截）";
  }
  return text;
}

function httpRequestOnce(method, opts) {
  return new Promise(function (resolve) {
    if (isQX) {
      opts.method = method;
      $task.fetch(opts).then(
        function (resp) {
          resolve({ body: resp.body, status: resp.statusCode });
        },
        function (err) {
          resolve({ error: describeHttpError((err && err.error) || err) });
        }
      );
    } else if (isSurgeLike) {
      // 注意：不能把 $httpClient.post 解引用成局部变量再调用 —— Shadowrocket 的
      // $httpClient 是 ObjC 桥接对象，脱离对象调用会抛
      // "self type check failed for Objective-C instance method"。必须直调。
      var cb = function (error, response, body) {
        if (error) resolve({ error: describeHttpError(error) });
        else resolve({ body: body, status: response && (response.status || response.statusCode) });
      };
      if (method === "POST") $httpClient.post(opts, cb);
      else $httpClient.get(opts, cb);
    } else {
      resolve({ error: "unsupported client" });
    }
  });
}

function delay(ms) {
  return new Promise(function (resolve) {
    if (typeof setTimeout === "function") setTimeout(resolve, ms);
    else resolve();
  });
}

// 移动网络下单次请求失败很常见（cron 触发时链路刚唤醒 / 切网瞬间）。
// 服务端对重复 IP 幂等，重试 POST /add 不会重复占坑或推进淘汰队列，因此可安全重试。
var HTTP_RETRY = 3;
var HTTP_RETRY_DELAY_MS = 1500;

function parseResponseBody(body) {
  try {
    return JSON.parse(body);
  } catch (e) {
    return null;
  }
}

function responseErrorStatus(status, data) {
  if (status && (status < 200 || status >= 300)) return Number(status);
  return data && typeof data.code === "number" && data.code >= 400 ? data.code : 0;
}

// 偶发的裸 400、限流和 5xx 可重试；明确的参数错误和槽位冲突直接报告。
function isRetryableServerError(r) {
  if (r.errorStatus === 429 || r.errorStatus >= 500) return true;
  return !!r.errorStatus && r.errorStatus !== 403 && r.data === null;
}

function httpRequest(method, opts, attempt) {
  attempt = attempt || 1;
  return httpRequestOnce(method, opts).then(function (r) {
    r.data = parseResponseBody(r.body);
    r.errorStatus = responseErrorStatus(r.status, r.data);
    if (!r.error && !isRetryableServerError(r)) return r;
    if (attempt >= HTTP_RETRY) {
      r.attempts = attempt;
      return r;
    }
    return delay(HTTP_RETRY_DELAY_MS * attempt).then(function () {
      return httpRequest(method, opts, attempt + 1);
    });
  });
}

function getArgumentTokens() {
  if (typeof $argument === "undefined" || $argument === null) return "";
  // Loon 插件 argument=[{tokens}] 会注入对象形态
  if (typeof $argument === "object") return String($argument.tokens || "");
  if (typeof $argument === "string") {
    var arg = $argument.trim();
    // Shadowrocket 等客户端可能把配置里的外层引号原样传入，先剥掉
    if (/^(["'])[\s\S]*\1$/.test(arg)) arg = arg.slice(1, -1).trim();
    // Loon 也可能注入 JSON 字符串
    if (arg.charAt(0) === "{") {
      try {
        return String(JSON.parse(arg).tokens || "");
      } catch (e) {}
    }
    // Surge/Stash 风格 tokens=xxx&...
    var pairs = arg.split("&");
    for (var i = 0; i < pairs.length; i++) {
      var idx = pairs[i].indexOf("=");
      if (idx > 0 && pairs[i].slice(0, idx).trim() === "tokens") {
        var value = pairs[i].slice(idx + 1).trim();
        try {
          return decodeURIComponent(value);
        } catch (e) {
          return value;
        }
      }
    }
    // 直接把整串当 token 填的兜底（如 Loon argument="pgnfw_..."）
    if (arg.indexOf("pgnfw_") === 0) return arg;
  }
  return "";
}

function parseTokenEntries(raw) {
  return String(raw || "")
    .split(/[,，|;、\s]+/)
    .filter(function (entry) {
      return entry.indexOf("pgnfw_") === 0;
    })
    .map(function (entry) {
      var at = entry.indexOf("@");
      var token = at < 0 ? entry : entry.slice(0, at);
      if (!/^pgnfw_[A-Za-z0-9_-]+$/.test(token)) {
        return { error: "token 格式无效" };
      }
      if (at < 0) return { token: token, slot: null };
      var slot = entry.slice(at + 1);
      if (!/^\d+$/.test(slot)) return { error: "槽位无效（须填数字，如 @0）" };
      return { token: token, slot: slot.replace(/^0+(?=\d)/, "") };
    });
}

function onCellular() {
  try {
    var iface =
      ($network.v4 && $network.v4.primaryInterface) ||
      ($network.v6 && $network.v6.primaryInterface) ||
      "";
    return iface.indexOf("pdp_ip") === 0;
  } catch (e) {
    return false; // 客户端不支持 $network 时按非蜂窝处理
  }
}

function finish(title, content, allOk) {
  if (isQX) {
    $done();
    return;
  }
  var result = { title: title, content: content };
  // 面板标题已有状态图标；Mac 上额外的 SF Symbol 会占据卡片空间。
  if (!isPanel) {
    result.icon = allOk ? "checkmark.shield" : "exclamationmark.shield";
    result["icon-color"] = allOk ? "#34C759" : "#FF3B30";
  }
  $done(result);
}

/* ---------- 业务逻辑 ---------- */

// 服务端按 C 段（/24）加白，条目可能是精确 IP 或 x.x.x.0/24。
// 任一侧为 /24 段时按前三段比较，两侧均为精确 IP 时要求全等。
function sameC24(a, b) {
  if (!a || !b) return false;
  a = String(a);
  b = String(b);
  if (a === b) return true;
  if (a.slice(-3) !== "/24" && b.slice(-3) !== "/24") return false;
  var pa = a.replace("/24", "").split(".");
  var pb = b.replace("/24", "").split(".");
  return (
    pa.length === 4 && pb.length === 4 && pa[0] === pb[0] && pa[1] === pb[1] && pa[2] === pb[2]
  );
}

function readHistory(key) {
  try {
    var h = JSON.parse(storeRead(key) || "[]");
    var cutoff = Date.now() - HIST_WINDOW_MS;
    return h.filter(function (e) {
      return e.ts > cutoff;
    });
  } catch (e) {
    return [];
  }
}

function apiCall(token, slot, readOnly) {
  // token 走 URL 路径；自动面板只读，其他触发命中 /add 加白
  var url = API_BASE + encodeURIComponent(token);
  if (!readOnly) url += "/add";
  if (!readOnly && slot !== null && slot !== undefined && slot !== "") {
    url += "?slot=" + encodeURIComponent(slot);
  }
  var opts = { url: url };
  if (!readOnly) {
    opts.headers = { "Content-Type": "application/json" };
    opts.body = "";
  }
  if (REQUEST_TIMEOUT !== null) opts.timeout = REQUEST_TIMEOUT;

  return httpRequest(readOnly ? "GET" : "POST", opts).then(function (r) {
    var attempts = r.attempts ? "（已尝试 " + r.attempts + " 次）" : "";
    if (r.error) return { error: r.error + attempts };
    var data = r.data;
    // 带槽位写入且本机 IP 已占用别的槽位 → 服务端 403 冲突，需去 UI 删旧槽位
    if (r.errorStatus === 403 && !readOnly && slot !== null) {
      return {
        error: "槽位冲突：本机 IP 已在其它槽位，请先去 UI 删除",
        conflict: true,
        currentIp: data && data.currentIp,
      };
    }
    if (r.errorStatus) {
      var reason = (data && (data.message || data.error)) || String(r.body || "").trim() || "请求失败";
      return { error: "HTTP " + r.errorStatus + "：" + String(reason).slice(0, 80) + attempts };
    }
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return { error: "响应异常: " + String(r.body).slice(0, 80) };
    }
    // whitelist 元素为 {ip, slot} 对象（旧版曾是纯 IP 字符串）：记下 ip→slot 再摊平成 IP 数组
    var raw = Array.isArray(data.whitelist) ? data.whitelist : [];
    data.slotOf = {};
    raw.forEach(function (e) {
      if (e && typeof e === "object" && e.slot !== null && e.slot !== undefined) {
        data.slotOf[e.ip] = e.slot;
      }
    });
    data.whitelist = raw.map(function (e) {
      return e && typeof e === "object" ? e.ip : e;
    });
    data.applied =
      (readOnly ? data.enabled !== false : data.enabled === true) &&
      data.whitelist.some(function (ip) {
        return sameC24(ip, data.currentIp);
      });
    return data;
  });
}

function ensureWhitelisted(item, index, readOnly) {
  var kvState = STORE_PREFIX + index;
  var kvHist = STORE_PREFIX + "hist_" + index;
  var cellular = onCellular();
  var ctx = { kvState: kvState, kvHist: kvHist, slot: item.slot };
  if (item.error) {
    ctx.st = { error: item.error };
    return Promise.resolve(ctx);
  }

  // 写入触发直接请求 /add；面板自动刷新只查询
  return apiCall(item.token, item.slot, readOnly).then(function (st) {
    if (!readOnly && st.applied) {
      var hist = readHistory(kvHist);
      var last = hist.length ? hist[hist.length - 1] : null;
      if (!last || last.ip !== st.currentIp) {
        hist.push({ ip: st.currentIp, src: cellular ? "cell" : "fixed", ts: Date.now() });
        storeWrite(JSON.stringify(hist.slice(-10)), kvHist);
      }
    }
    ctx.st = st;
    return ctx;
  });
}

// 每 token 一行：不含 token，只含白名单/坑位信息；蜂窝加的 IP 标 📶
function describe(index, ctx) {
  var st = ctx.st;
  var pin = ctx.slot !== null && ctx.slot !== undefined && ctx.slot !== "" ? " 📌" + ctx.slot : "";
  var head = "#" + (index + 1) + pin + " ";
  if (st.error) return head + "❌ " + st.error;
  if (st.enabled === false) return head + "⚠️ 防火墙未启用";
  if (!st.applied) return head + "❌ 加白未生效 " + st.whitelist.length + "/" + st.limit;

  var hist = readHistory(ctx.kvHist);
  var cellIps = {};
  hist.forEach(function (e) {
    if (e.src === "cell") cellIps[e.ip] = true;
  });
  var slotOf = st.slotOf || {};
  var ips = st.whitelist
    .map(function (ip) {
      var slotTag = slotOf[ip] !== undefined ? " 📌" + slotOf[ip] : "";
      return ip + slotTag + (cellIps[ip] ? " 📶" : "") + (sameC24(ip, st.currentIp) ? " ←" : "");
    })
    .join("\n    ");
  return head + "✅ " + st.whitelist.length + "/" + st.limit + "\n    " + ips;
}

function panelTime() {
  var now = new Date();
  var hours = now.getHours();
  var minutes = now.getMinutes();
  return (hours < 10 ? "0" : "") + hours + ":" + (minutes < 10 ? "0" : "") + minutes;
}

function panelSummaryLine(index, ctx, single) {
  var st = ctx.st;
  var head = single ? "" : "#" + (index + 1) + " ";
  if (st.error) return head + "❌ " + st.error;
  if (st.enabled === false) return head + "⚠️ 防火墙未启用";
  var count = st.whitelist.length + "/" + st.limit;
  if (!st.applied) return head + "❌ 当前出口未加白 · 白名单 " + count;
  return single ? "白名单占用 " + count : head + "已加白 · 占用 " + count;
}

function panelDetailPages(results, summaryTitle) {
  var pages = [];
  results.forEach(function (ctx, index) {
    var st = ctx.st;
    var title = results.length === 1 ? summaryTitle : PANEL_TITLE + " · #" + (index + 1) + "/" + results.length;
    if (st.error || st.enabled === false || !st.applied) {
      pages.push({
        title: title,
        content: "出口 " + (st.currentIp || "未知") + "\n" + panelSummaryLine(index, ctx, true),
      });
      return;
    }

    // 标题显示机器和页码，正文每页留给最多五条完整 IP，避免窄面板截断。
    var pageCount = Math.ceil(st.whitelist.length / PANEL_DETAIL_PAGE_SIZE);
    for (var page = 0; page < pageCount; page++) {
      var start = page * PANEL_DETAIL_PAGE_SIZE;
      var lines = st.whitelist.slice(start, start + PANEL_DETAIL_PAGE_SIZE).map(function (ip) {
        return ip + (sameC24(ip, st.currentIp) ? " ←" : "");
      });
      pages.push({
        title: pageCount === 1 ? title : title + " · " + (page + 1) + "/" + pageCount,
        content: lines.join("\n"),
      });
    }
  });
  return pages;
}

function panelDisplay(results, okCount, exitIp) {
  var allOk = okCount === results.length;
  var title =
    PANEL_TITLE + " " +
    (allOk ? "✅" : okCount > 0 ? "⚠️" : "❌") +
    " " +
    okCount +
    "/" +
    results.length;
  // 手动刷新已经执行 POST。逐页显示明细，翻完或自动刷新时回到简要。
  if (!isAutoPanel) {
    var nextPage = Number(storeRead(PANEL_DETAIL_KEY) || 0);
    var detail = panelDetailPages(results, title)[nextPage];
    if (detail) {
      storeWrite(String(nextPage + 1), PANEL_DETAIL_KEY);
      finish(detail.title, detail.content, allOk);
      return;
    }
  }

  var lines = ["出口 " + (exitIp === "?" ? "未知" : exitIp)];
  results.forEach(function (ctx, index) {
    lines.push(panelSummaryLine(index, ctx, results.length === 1));
  });
  // 单 token 简要状态补两行有用的信息，与 5 条 IP 明细的高度相近，
  // 避免 Mac 面板标题和内容之间出现大块空白；iOS 显示保持一致。
  if (results.length === 1) {
    var st = results[0].st;
    if (!st.error && st.enabled !== false && st.applied) {
      lines.splice(1, 0, "防火墙 已启用");
      lines.push("手动刷新：加白并看明细");
    }
  }
  lines.push("更新 " + panelTime());
  storeWrite("0", PANEL_DETAIL_KEY);
  finish(title, lines.join("\n"), allOk);
}

var tokens = parseTokenEntries(getArgumentTokens() || storeRead(TOKENS_KEY) || INLINE_TOKENS);

if (tokens.length === 0) {
  if (isPanel) {
    finish(PANEL_TITLE + " ❌ 0/0", "未配置 token\n更新 " + panelTime(), false);
  } else {
    notify(
      "po0 防火墙加白",
      "未配置 token",
      "模块参数 tokens / 存储 key po0fw_tokens / 脚本内 INLINE_TOKENS 三选一填入 pgnfw_ token"
    );
    finish("po0 加白：未配置 token", "请填入 pgnfw_ token，多个用英文逗号分隔（Shadowrocket 用 |）", false);
  }
} else {
  Promise.all(
    tokens.map(function (t, i) {
      return ensureWhitelisted(t, i, isAutoPanel);
    })
  ).then(function (results) {
    var okCount = 0;
    var exitIp = "?";
    var lines = [];
    var changed = false;

    for (var i = 0; i < results.length; i++) {
      var st = results[i].st;
      if (st.applied) okCount++;
      if (st.currentIp) exitIp = st.currentIp;
      if (!isPanel) lines.push(describe(i, results[i]));

      if (!isPanel) {
        var state = (st.currentIp || "?") + "|" + (st.applied ? "1" : "0");
        if (storeRead(results[i].kvState) !== state) {
          storeWrite(state, results[i].kvState);
          changed = true;
        }
      }
    }

    if (isPanel) {
      panelDisplay(results, okCount, exitIp);
      return;
    }

    var allOk = okCount === results.length;
    var title =
      "po0 加白 " + okCount + "/" + results.length + " · 出口 " + exitIp + (onCellular() ? " 📶" : "");
    var content = lines.join("\n");

    // 成功态仅在出口 IP / 加白状态变化时通知；失败/未生效必须每次弹，
    // 否则持久化状态相同（都是失败）时 changed=false 会把错误静默吞掉。
    if (changed || !allOk) {
      notify("po0 防火墙加白", title, content);
    }
    finish(title, content, allOk);
  }).catch(function (e) {
    var message = String(e && e.message ? e.message : e);
    if (isPanel) finish(PANEL_TITLE + " ❌", "脚本异常：" + message, false);
    else {
      notify("po0 防火墙加白", "脚本异常", message);
      finish("po0 加白：脚本异常", message, false);
    }
  });
}
