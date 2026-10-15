import base64, hashlib, struct
from flask import Flask, request
from Crypto.Cipher import AES

# ====== 填入企微「接收消息服务器配置」页面上的两个值 ======
TOKEN = "替换成页面上的Token"
AES_KEY_B64 = "替换成页面上的EncodingAESKey"  # 43位字符
# ========================================================

AES_KEY = base64.b64decode(AES_KEY_B64 + "=")


def decrypt(msg_signature, timestamp, nonce, echostr):
    """验证并解密企微回调, 返回明文或 None"""
    s = "".join(sorted([TOKEN, timestamp, nonce, echostr]))
    if hashlib.sha1(s.encode()).hexdigest() != msg_signature:
        return None
    c = AES.new(AES_KEY, AES.MODE_CBC, AES_KEY[:16])
    p = c.decrypt(base64.b64decode(echostr))
    p = p[16:-p[-1]]
    xml = p[4:4 + struct.unpack(">I", p[:4])[0]]
    return xml.decode("utf-8", errors="replace")


@app.get("/wecom/callback")
def verify():
    a = request.args
    plain = decrypt(a.get("msg_signature", ""), a.get("timestamp", ""),
                    a.get("nonce", ""), a.get("echostr", ""))
    return (plain, 200) if plain else ("fail", 403)


@app.post("/wecom/callback")
def receive():
    """事件消息推送: 解密 XML, 简单打印并应答"""
    a = request.args
    # POST 的加密内容在 body 的 XML 里 <Encrypt> 字段, 先直接解密整包试试
    try:
        import re
        m = re.search(r"<Encrypt><!\[CDATA\[(.*?)\]\]></Encrypt>", request.data.decode())
        if m:
            plain = decrypt(a.get("msg_signature", ""), a.get("timestamp", ""),
                            a.get("nonce", ""), m.group(1))
            print("收到事件:", plain, flush=True)
    except Exception as e:
        print("解密失败:", e, flush=True)
    return "success"


app = Flask(__name__)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
