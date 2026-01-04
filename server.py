import socket
import threading
import struct
import json
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES

# ================= 配置区域 =================
HOST = '0.0.0.0'  # 监听所有网卡，允许 Windows 物理机连接
PORT = 9999       # 监听端口
# ===========================================

def send_packet(sock, data_bytes):
    """辅助函数：发送带长度前缀的数据包"""
    # 4字节大端序长度 + 数据本体
    sock.sendall(struct.pack('>I', len(data_bytes)) + data_bytes)

def recv_packet(sock):
    """辅助函数：接收带长度前缀的数据包"""
    raw_len = sock.recv(4)
    if not raw_len: return None
    msg_len = struct.unpack('>I', raw_len)[0]
    data = b''
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data))
        if not packet: return None
        data += packet
    return data

def handle_client(conn, addr):
    print(f"\n[Server] 收到来自 {addr} 的连接")
    
    try:
        # -----------------------------------------------------------
        # 第一步：准备身份密钥 (RSA) 和 协商参数 (Diffie-Hellman)
        # -----------------------------------------------------------
        print("[Server] 1. 正在生成 RSA 身份密钥对 (2048 bit)...")
        server_rsa_key = RSA.generate(2048)
        server_rsa_pub_pem = server_rsa_key.publickey().export_key()

        print("[Server] 2. 正在生成 Diffie-Hellman 参数 (大素数 P 和生成元 G)...")
        # 教学演示用 1024 位素数 (生产环境建议 2048+)
        dh_p = number.getPrime(1024) 
        dh_g = 2
        
        # 生成服务端 DH 私钥 a 和 公钥 A
        # A = g^a mod p
        dh_priv_a = number.getRandomRange(2, dh_p - 1)
        dh_pub_A = pow(dh_g, dh_priv_a, dh_p)

        # -----------------------------------------------------------
        # 第二步：对 DH 参数进行数字签名 (防范中间人攻击的核心)
        # -----------------------------------------------------------
        print("[Server] 3. 对 DH 参数进行 RSA 签名...")
        # 将要发送的关键参数拼接成字符串进行哈希
        # 签名内容包括：g, p, A
        sign_payload = f"{dh_g},{dh_p},{dh_pub_A}".encode('utf-8')
        h = SHA256.new(sign_payload)
        signature = pkcs1_15.new(server_rsa_key).sign(h)

        # -----------------------------------------------------------
        # 第三步：发送握手数据包
        # -----------------------------------------------------------
        print("[Server] 4. 发送握手包 (RSA公钥 + DH参数 + 签名)...")
        handshake_data = {
            'rsa_pub': server_rsa_pub_pem.decode('utf-8'),
            'p': dh_p,
            'g': dh_g,
            'A': dh_pub_A,
            # 签名转 hex 字符串方便传输
            'sig': signature.hex() 
        }
        send_packet(conn, json.dumps(handshake_data).encode('utf-8'))

        # -----------------------------------------------------------
        # 第四步：等待客户端回传 DH 公钥 B
        # -----------------------------------------------------------
        print("[Server] 5. 等待客户端回传 DH 公钥 B...")
        client_data_bytes = recv_packet(conn)
        if not client_data_bytes:
            print("[Server] 客户端断开连接")
            return
            
        client_data = json.loads(client_data_bytes)
        dh_pub_B = client_data['B']
        print(f"[Server] 收到客户端 DH 公钥 B: {str(dh_pub_B)[:20]}...")

        # -----------------------------------------------------------
        # 第五步：计算共享密钥并派生 AES 密钥
        # -----------------------------------------------------------
        # S = B^a mod p
        shared_secret = pow(dh_pub_B, dh_priv_a, dh_p)
        
        # 使用 SHA-256 将大整数 S 转换为 32字节的 AES Key
        aes_key = SHA256.new(str(shared_secret).encode('utf-8')).digest()
        print(f"[Server] 🔑 密钥协商成功！AES Key (SHA256): {aes_key.hex()[:20]}...")

        # -----------------------------------------------------------
        # 第六步：进入加密聊天循环 (AES-GCM)
        # -----------------------------------------------------------
        print("[Server] --- 安全通道建立完毕，开始接收消息 ---")
        
        def receive_loop():
            while True:
                try:
                    encrypted_packet = recv_packet(conn)
                    if not encrypted_packet: break

                    # 解析结构: Nonce(16) + Tag(16) + Ciphertext(N)
                    nonce = encrypted_packet[:16]
                    tag = encrypted_packet[16:32]
                    ciphertext = encrypted_packet[32:]

                    # 解密
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    print(f"\n[Client]: {plaintext.decode('utf-8')}")
                except Exception as e:
                    print(f"[Server] 解密失败或连接断开: {e}")
                    break
        
        # 开启接收线程
        recv_thread = threading.Thread(target=receive_loop, daemon=True)
        recv_thread.start()

        # 发送循环
        while True:
            msg = input()
            if not msg: break
            
            # 加密: AES-GCM
            cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
            
            # 发送结构: Nonce + Tag + Ciphertext
            send_packet(conn, cipher.nonce + tag + ciphertext)

    except Exception as e:
        print(f"[Server] 发生错误: {e}")
    finally:
        conn.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[Server] 正在监听 {HOST}:{PORT}，等待 Windows 客户端连接...")
    
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr))
        t.start()

if __name__ == '__main__':
    start_server()