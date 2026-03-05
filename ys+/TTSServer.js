const http = require('http');
// url 模块仅保留兼容引用，优先使用 WHATWG URL API
const tls = require('tls');
const crypto = require('crypto');
const axios = require('axios');

const PORT = 3000;
const CHROMIUM_VER = '144.0.3719.82';
const CLIENT_TOKEN = '6A5AA1D4EAFF4E9FB37E23D68491D6F4';
const WIN_EPOCH = 11644473600n;

// ==================== 轻量 WebSocket 客户端 ====================

class TinyWS {
    /**
     * 基于 tls 的最小 WebSocket 客户端，替代 ws 库
     * 支持 text/binary/close/ping-pong 帧
     */
    constructor(wsUrl, opts = {}) {
        this.onopen = this.onmessage = this.onclose = this.onerror = null;
        this._buf = Buffer.alloc(0);
        this._ready = false;
        this._closed = false;

        const u = new URL(wsUrl);
        const host = u.hostname;
        const port = parseInt(u.port) || 443;
        const wsKey = crypto.randomBytes(16).toString('base64');

        // 构造 HTTP Upgrade 请求
        const lines = [
            `GET ${u.pathname}${u.search} HTTP/1.1`,
            `Host: ${opts.host || host}`,
            `Upgrade: websocket`,
            `Connection: Upgrade`,
            `Sec-WebSocket-Key: ${wsKey}`,
            `Sec-WebSocket-Version: 13`,
        ];
        if (opts.origin) lines.push(`Origin: ${opts.origin}`);
        if (opts.headers) {
            for (const [k, v] of Object.entries(opts.headers)) lines.push(`${k}: ${v}`);
        }

        this.socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false }, () => {
            this.socket.write(lines.join('\r\n') + '\r\n\r\n');
        });
        this.socket.on('data', (d) => this._onData(d));
        this.socket.on('error', (e) => this.onerror && this.onerror(e));
        this.socket.on('close', () => {
            if (!this._closed) { this._closed = true; this.onclose && this.onclose({ code: 1006 }); }
        });
    }

    _onData(chunk) {
        this._buf = Buffer.concat([this._buf, chunk]);
        if (!this._ready) {
            const i = this._buf.indexOf('\r\n\r\n');
            if (i === -1) return;
            const hdr = this._buf.slice(0, i).toString();
            this._buf = this._buf.slice(i + 4);
            if (hdr.includes('101')) {
                this._ready = true;
                this.onopen && this.onopen();
                this._drain();
            } else {
                this.onerror && this.onerror(new Error('Upgrade failed: ' + hdr.split('\r\n')[0]));
                this.socket.destroy();
            }
        } else {
            this._drain();
        }
    }

    /** 循环解析所有完整的 WebSocket 帧 */
    _drain() {
        while (this._buf.length >= 2) {
            const op = this._buf[0] & 0x0F;
            const masked = (this._buf[1] & 0x80) !== 0;
            let len = this._buf[1] & 0x7F;
            let off = 2;

            if (len === 126) {
                if (this._buf.length < 4) return;
                len = this._buf.readUInt16BE(2); off = 4;
            } else if (len === 127) {
                if (this._buf.length < 10) return;
                len = this._buf.readUInt32BE(6); off = 10; // 高4字节忽略，TTS音频不会超过4GB
            }
            if (masked) off += 4;
            if (this._buf.length < off + len) return;

            let payload = this._buf.slice(off, off + len);
            if (masked) {
                const mk = this._buf.slice(off - 4, off);
                payload = Buffer.from(payload);
                for (let i = 0; i < payload.length; i++) payload[i] ^= mk[i % 4];
            }
            this._buf = this._buf.slice(off + len);

            if (op === 1) this.onmessage && this.onmessage({ data: payload.toString('utf-8') });
            else if (op === 2) this.onmessage && this.onmessage({ data: payload });
            else if (op === 8) { this._closed = true; this.onclose && this.onclose({ code: payload.length >= 2 ? payload.readUInt16BE(0) : 1000 }); this.socket.end(); }
            else if (op === 9) this._writeFrame(0xA, payload); // pong
        }
    }

    /** 发送带 mask 的帧（RFC 6455 客户端必须 mask） */
    _writeFrame(op, data) {
        const pl = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf-8');
        const mask = crypto.randomBytes(4);
        let hdr;
        if (pl.length < 126) {
            hdr = Buffer.alloc(2);
            hdr[0] = 0x80 | op; hdr[1] = 0x80 | pl.length;
        } else if (pl.length < 65536) {
            hdr = Buffer.alloc(4);
            hdr[0] = 0x80 | op; hdr[1] = 0x80 | 126;
            hdr.writeUInt16BE(pl.length, 2);
        } else {
            hdr = Buffer.alloc(10);
            hdr[0] = 0x80 | op; hdr[1] = 0x80 | 127;
            hdr.writeUInt32BE(0, 2); hdr.writeUInt32BE(pl.length, 6);
        }
        const masked = Buffer.alloc(pl.length);
        for (let i = 0; i < pl.length; i++) masked[i] = pl[i] ^ mask[i % 4];
        this.socket.write(Buffer.concat([hdr, mask, masked]));
    }

    /** 发送文本/二进制数据，兼容 ws 库的回调风格 */
    send(data, cb) {
        try { this._writeFrame(Buffer.isBuffer(data) ? 2 : 1, data); cb && cb(null); }
        catch (e) { cb && cb(e); }
    }

    /** 主动关闭 */
    close(code, reason) {
        if (this._closed) return;
        code = code || 1000; reason = reason || '';
        const rb = Buffer.from(reason, 'utf-8');
        const p = Buffer.alloc(2 + rb.length);
        p.writeUInt16BE(code, 0); rb.copy(p, 2);
        this._writeFrame(8, p);
        this._closed = true;
        this.socket.end();
    }
}

// ==================== 工具函数 ====================

/** 生成 Sec-MS-GEC 令牌 */
function makeGecToken() {
    const ticks = BigInt(Math.floor(Date.now() / 1000 + Number(WIN_EPOCH))) * 10000000n;
    const rounded = ticks - (ticks % 3000000000n);
    return crypto.createHash('sha256').update(`${rounded}${CLIENT_TOKEN}`, 'ascii').digest('hex').toUpperCase();
}

/** 生成 32 位十六进制随机 ID */
function randHex32() {
    const c = 'abcdef0123456789';
    let s = '';
    for (let i = 0; i < 32; i++) s += c[Math.random() * 16 | 0];
    return s;
}

/** 构造 SSML 文本 */
function buildSSML(text, voice, volume, rate, pitch) {
    const esc = String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
    return `<speak version="1.0" xml:lang="en-US" xmlns="http://www.w3.org/2001/10/synthesis" xmlns:mstts="http://www.w3.org/2001/mstts" xmlns:emo="http://www.w3.org/2009/10/emotionml">
  <voice name="${voice}">
    <prosody pitch="${pitch}%" rate="${rate}%" volume="${volume}%">${esc}</prosody>
  </voice>
</speak>`;
}

/** 解析 WebSocket 消息头部 */
function parseHeader(str) {
    const rid = (/X-RequestId:([a-z0-9]*)/i.exec(str) || [])[1] || '';
    const path = (/Path:(.*)/i.exec(str) || [])[1] || '';
    return { requestId: rid.trim(), path: path.trim() };
}

// ==================== MP3 首尾静音裁剪 ====================

/** 解析单个 MP3 帧头，返回帧大小（字节），无效返回 0 */
function mp3FrameSize(buf, off) {
    if (off + 4 > buf.length) return 0;
    if (buf[off] !== 0xFF || (buf[off + 1] & 0xE0) !== 0xE0) return 0;
    const h = (buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
    const ver = (h >> 19) & 3, lyr = (h >> 17) & 3;
    const brI = (h >> 12) & 0xF, srI = (h >> 10) & 3, pad = (h >> 9) & 1;
    if (ver === 1 || lyr === 0 || brI === 0 || brI === 15 || srI === 3) return 0;

    const sr = ({ 3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000] })[ver];
    if (!sr) return 0;
    const brKey = (ver === 3 ? 'a' : 'b') + lyr;
    const brTab = {
        a3: [0,32,64,96,128,160,192,224,256,288,320,352,384,416,448],   // V1 L1
        a2: [0,32,48,56,64,80,96,112,128,160,192,224,256,320,384],      // V1 L2
        a1: [0,32,40,48,56,64,80,96,112,128,160,192,224,256,320],       // V1 L3
        b3: [0,32,48,56,64,80,96,112,128,144,160,176,192,224,256],      // V2 L1
        b2: [0,8,16,24,32,40,48,56,64,80,96,112,128,144,160],           // V2 L2
        b1: [0,8,16,24,32,40,48,56,64,80,96,112,128,144,160],           // V2 L3
    };
    const br = brTab[brKey] && brTab[brKey][brI];
    if (!br) return 0;
    const bitrate = br * 1000, sampleRate = sr[srI];
    if (lyr === 3) return Math.floor((12 * bitrate / sampleRate + pad) * 4);       // Layer I
    if (ver === 3) return Math.floor(144 * bitrate / sampleRate + pad);             // MPEG1 L2/L3
    return Math.floor(72 * bitrate / sampleRate + pad);                             // MPEG2 L2/L3
}

/**
 * 裁剪 MP3 首尾编码器填充帧，减少段落间留白
 * 跳过首帧（编码器延迟 ~24ms）和末帧（填充静音 ~24ms）
 */
function trimMP3(buf) {
    let pos = 0;
    // 跳过 ID3v2 标签
    if (buf.length > 10 && buf[0] === 0x49 && buf[1] === 0x44 && buf[2] === 0x33) {
        pos = 10 + ((buf[6] & 0x7F) << 21 | (buf[7] & 0x7F) << 14 | (buf[8] & 0x7F) << 7 | (buf[9] & 0x7F));
    }
    // 逐帧扫描，记录每帧的偏移和大小
    const frames = [];
    while (pos < buf.length - 4) {
        const size = mp3FrameSize(buf, pos);
        if (size > 0) { frames.push({ off: pos, size }); pos += size; }
        else pos++;
    }
    if (frames.length <= 4) return buf; // 太短不裁剪
    // 去掉首帧 + 末帧
    const start = frames[1].off;
    const last = frames[frames.length - 2];
    return buf.slice(start, last.off + last.size);
}

/** 返回 JSON 响应 */
function json(res, code, data) {
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
}

// ==================== WebSocket 连接 ====================

function connectWS() {
    const connId = randHex32();
    const gec = makeGecToken();
    const url = `wss://speech.platform.bing.com/consumer/speech/synthesize/readaloud/edge/v1?TrustedClientToken=${CLIENT_TOKEN}&Sec-MS-GEC=${gec}&Sec-MS-GEC-Version=1-${CHROMIUM_VER}&ConnectionId=${connId}`;

    const ws = new TinyWS(url, {
        host: 'speech.platform.bing.com',
        origin: 'chrome-extension://jdiccldimpdaibmpdkjnbmckianbfold',
        headers: { 'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 Edg/144.0.0.0' },
    });

    return new Promise((resolve, reject) => {
        const t = setTimeout(() => { ws.close(); reject(new Error('WS connect timeout')); }, 10000);
        ws.onopen = () => { clearTimeout(t); resolve(ws); };
        ws.onerror = (e) => { clearTimeout(t); reject(e); };
    });
}

// ==================== 发音人 ====================

const VOICE_CN = {
    'zh-HK-HiuGaaiNeural': '曉佳', 'zh-HK-HiuMaanNeural': '曉曼', 'zh-HK-WanLungNeural': '雲龍',
    'zh-CN-XiaoxiaoNeural': '晓晓', 'zh-CN-XiaoyiNeural': '晓伊', 'zh-CN-YunjianNeural': '云健',
    'zh-CN-YunxiNeural': '云希', 'zh-CN-YunxiaNeural': '云夏', 'zh-CN-YunyangNeural': '云扬',
    'zh-CN-liaoning-XiaobeiNeural': '晓北', 'zh-TW-HsiaoChenNeural': '曉臻',
    'zh-TW-YunJheNeural': '雲哲', 'zh-TW-HsiaoYuNeural': '曉雨', 'zh-CN-shaanxi-XiaoniNeural': '晓妮',
};

let _voicesCache = null, _cacheTs = 0;

/** 获取发音人列表（带1小时缓存） */
async function getVoices() {
    if (_voicesCache && Date.now() - _cacheTs < 3600000) return _voicesCache;
    const r = await axios.get(
        `https://speech.platform.bing.com/consumer/speech/synthesize/readaloud/voices/list?trustedclienttoken=${CLIENT_TOKEN}`,
        { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' } }
    );
    _voicesCache = r.data;
    _cacheTs = Date.now();
    return _voicesCache;
}

/** 获取友好名称 */
function friendly(short, full) {
    if (VOICE_CN[short]) return VOICE_CN[short];
    const p = full.split('-');
    return p.length >= 2 ? p[0].replace('Microsoft', '').replace('Online', '').replace('(Natural)', '').trim() : full;
}

// ==================== TTS 核心 ====================

async function synthesize(ssml) {
    const reqId = randHex32();
    const ws = await connectWS();
    console.log('[TTS] connected, reqId=' + reqId);

    return new Promise((resolve, reject) => {
        let audio = Buffer.alloc(0), done = false;

        const finish = () => { if (!done) { done = true; clearTimeout(timer); } };

        const timer = setTimeout(() => {
            finish(); ws.close(1000, 'timeout');
            reject(new Error('Timeout: 60s'));
        }, 60000);

        ws.onclose = (r) => {
            if (!done) { finish(); audio.length > 0 ? resolve(audio) : reject(new Error('WS closed: ' + r.code)); }
        };
        ws.onerror = (e) => { if (!done) { finish(); reject(e); } };

        ws.onmessage = (msg) => {
            try {
                if (Buffer.isBuffer(msg.data)) {
                    // 二进制帧 → 音频数据
                    const buf = msg.data;
                    const hdrLen = buf[1];
                    const hdr = parseHeader(buf.slice(2, 2 + hdrLen).toString('utf-8'));
                    if (hdr.requestId === reqId) {
                        const chunk = buf.slice(2 + hdrLen);
                        if (chunk.length > 0) audio = Buffer.concat([audio, chunk]);
                    }
                } else if (typeof msg.data === 'string') {
                    // 文本帧 → 控制消息
                    const sep = msg.data.indexOf('\r\n\r\n');
                    if (sep === -1) return;
                    const hdr = parseHeader(msg.data.slice(0, sep));
                    if (hdr.path === 'turn.end' && hdr.requestId === reqId) {
                        finish(); ws.close(1000, 'done'); resolve(audio);
                    }
                }
            } catch (e) { console.error('[TTS] parse error:', e.message); }
        };

        // 发送配置
        const cfg = `X-Timestamp:${new Date().toISOString()}\r\nContent-Type:application/json; charset=utf-8\r\nPath:speech.config\r\n\r\n` +
            JSON.stringify({ context: { synthesis: { audio: { metadataoptions: { sentenceBoundaryEnabled: 'false', wordBoundaryEnabled: 'false' }, outputFormat: 'audio-24khz-96kbitrate-mono-mp3' } } } });

        ws.send(cfg, (err) => {
            if (err) { finish(); return reject(err); }
            // 发送 SSML
            const body = `X-Timestamp:${new Date().toISOString()}\r\nX-RequestId:${reqId}\r\nContent-Type:application/ssml+xml\r\nPath:ssml\r\n\r\n` + ssml;
            ws.send(body, (err) => { if (err) { finish(); reject(err); } });
        });
    });
}

// ==================== 路由处理 ====================

/** GET /api/voices */
async function routeVoices(req, res) {
    try { json(res, 200, await getVoices()); }
    catch (e) { json(res, 500, { error: e.message }); }
}

/** GET /api/speakers */
async function routeSpeakers(req, res, q) {
    try {
        const data = await getVoices();
        let list = data.map(v => ({
            name: v.ShortName,
            friendlyName: friendly(v.ShortName, v.FriendlyName),
            gender: v.Gender,
            locale: v.Locale,
            personalities: (v.VoiceTag && v.VoiceTag.VoicePersonalities) || [],
        }));
        if (q.locale) list = list.filter(v => v.locale.toLowerCase().startsWith(q.locale.toLowerCase()));
        const grouped = {};
        for (const v of list) { (grouped[v.locale] = grouped[v.locale] || []).push(v); }
        json(res, 200, { total: list.length, locales: Object.keys(grouped).sort(), voices: q.locale ? list : grouped });
    } catch (e) { json(res, 500, { error: e.message }); }
}

/** GET /api/text-to-speech */
async function routeTTS(req, res, q) {
    const t0 = Date.now();
    try {
        const authToken = (req.headers.authorization || '').split(' ')[1];
        if (process.env.TOKEN && authToken !== process.env.TOKEN) return json(res, 401, { error: 'Unauthorized' });

        let text = q.text;
        if (!text) return json(res, 400, { error: 'text is required' });

        text = decodeURIComponent(text);
        const voice = q.voice || 'zh-CN-XiaoxiaoNeural';
        const volume = parseInt(q.volume) || 100;
        const rate = parseInt(q.rate) || 0;
        const pitch = parseInt(q.pitch) || 0;
        const personality = q.personality || undefined; // 风格标签（透传，不影响合成）

        const raw = await synthesize(buildSSML(text, voice, volume, rate, pitch));
        const buf = trimMP3(raw);
        console.log('[TTS] OK ' + raw.length + 'B -> ' + buf.length + 'B (trimmed) in ' + (Date.now() - t0) + 'ms');
        res.writeHead(200, { 'Content-Type': 'audio/mpeg' });
        res.end(buf);
    } catch (e) {
        console.error('[TTS] ERR:', e.message);
        json(res, 500, { error: e.message });
    }
}

// ==================== HTTP 服务器 ====================

http.createServer(async (req, res) => {
    const parsed = new URL(req.url, 'http://127.0.0.1');
    const path = parsed.pathname;
    const q = Object.fromEntries(parsed.searchParams);

    if (req.method !== 'GET') return json(res, 405, { error: 'Method Not Allowed' });

    if (path === '/api/voices') await routeVoices(req, res);
    else if (path === '/api/speakers') await routeSpeakers(req, res, q);
    else if (path === '/api/text-to-speech') await routeTTS(req, res, q);
    else json(res, 404, { error: 'Not Found' });
}).listen(PORT, '0.0.0.0', () => {
    console.log('\n=== 微软TTS服务 ===');
    console.log('http://127.0.0.1:' + PORT);
    console.log('\n支持的API:');
    console.log('  GET /api/text-to-speech?text=hello&voice=zh-CN-XiaoxiaoNeural');
    console.log('  GET /api/speakers?locale=zh-CN');
    console.log('  GET /api/voices\n\n');
    console.log('请在小说朗读设置中配置以下地址即可');
    console.log('http://127.0.0.1:' + PORT + '/');


});
