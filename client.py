import socket
import threading
import struct
import json
import time


from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES
from Crypto.Util import number


#配置区域
#这里填linux服务器IP，或者运行程序时再输入
SERVER_IP = '192.168.4.101' 
SERVER_PORT = 9999




def send_packet(sock, data_bytes):
    """辅助函数：发送数据包 (4字节长度头 + 数据体)"""
    sock.sendall(struct.pack('>I', len(data_bytes)) + data_bytes)

def recv_packet(sock):
    """辅助函数：接收数据包"""
    raw_len = sock.recv(4)
    if not raw_len: return None
    msg_len = struct.unpack('>I', raw_len)[0]

    data = b''
    while len(data) < msg_len:
        packet = sock.recv(msg_len - len(data))
        if not packet: return None
        data += packet
    return data

def start_client():
    # 1. 输入服务器 IP
    target_ip = input(f"请输入服务器IP (默认 {SERVER_IP}): ").strip()
    if not target_ip:
        target_ip = SERVER_IP

    # 2. 【新增】询问用户是否开启攻击演示
    print("-" * 50)
    user_choice = input("是否模拟中间人攻击(篡改密钥)? (输入 y 开启，直接回车跳过): ").strip().lower()
    enable_tamper = (user_choice == 'y')
    if enable_tamper:
        print("[System]  已开启攻击模式：稍后将篡改收到的公钥。")
    else:
        print("[System]  正常模式：将进行合法的密钥协商。")
    print("-" * 50)

    print(f"[Client]  正在连接 {target_ip}:{SERVER_PORT} ...")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((target_ip, SERVER_PORT))
        print("[Client]  TCP 连接已建立。")
        
        print("[System]  开始进行加密握手协议")
        start_time = time.perf_counter() # 开始计时

        # 第一步：接收服务端的握手参数

        print("[Client]  1.接收服务端握手数据")
        packet = recv_packet(client)
        if not packet: 
            print("[Client]  未收到数据，连接断开")
            return

        # 解析 JSON 数据
        data = json.loads(packet)
        server_rsa_pem_str = data['rsa_pub'] # 这是服务端发来的原始 RSA 公钥字符串
        p = data['p']
        g = data['g']
        A = data['A']
        signature_hex = data['sig']
        
        print(f"[Client]  收到参数: P长度={len(str(p))}位, DH公钥A={str(A)[:10]}...")

        
        # 模拟中间人攻击模拟逻辑

        if enable_tamper:
            print("\n" + "="*50)
            print("[System]  模拟中间人攻击")
            print("[System]  正在尝试篡改公钥数据")
            
            #模拟中间人攻击，修改密钥
            # 1. Python 中的字符串是不可变的，所以先转成列表(List)方便修改
            pem_list = list(server_rsa_pem_str)
            
            # 2. 计算修改位置，选择修改字符串正中间的那个字符(RSA公钥很长，改中间肯定能破坏掉它的结构或数值)
            
            target_idx = len(pem_list) // 2
            original_char = pem_list[target_idx]
            
            # 3. 执行修改：如果原字符是 'A' 就改成 'B'，其他改成 'A'，模拟修改比特位。
            new_char = 'B' if original_char == 'A' else 'A'
            pem_list[target_idx] = new_char
            
            # 4. 将列表重新拼回字符串，这就得到了一个“被污染”的假公钥
            server_rsa_pem_str = "".join(pem_list)
            
            print(f"[System]  篡改位置: 第 {target_idx} 个字符")
            print(f"[System]  修改前: '{original_char}' -> 修改后: '{new_char}'")
            print("[System]  篡改完成，服务器给出的公钥已经被修改。")
            print("="*50 + "\n")

        # 第二步：验证数字签名 (RSA)

        print("[Client]  2.正在验证服务端 RSA 签名")
        
        # 准备用于验签的数据：必须和服务端签名时的内容和顺序完全一致
        verify_payload = f"{g},{p},{A}".encode('utf-8')
        h = SHA256.new(verify_payload)
        
        try:
            # 1. 导入公钥
            # 如果上面开启了攻击模式，这里的 server_rsa_pem_str 就是被改过的假公钥，会导致 import_key 报错(格式错误)，或者后面的 verify 报错(签名不对)
            server_rsa_pub = RSA.import_key(server_rsa_pem_str.encode('utf-8'))
            
            # 2. 验证签名
            # 用（可能被篡改的）公钥去验证签名，如果公钥不对，数学上是不可能验签通过的
            pkcs1_15.new(server_rsa_pub).verify(h, bytes.fromhex(signature_hex))
            
            print("[Client]  签名验证成功！服务端身份可信。")

        except (ValueError, IndexError, TypeError) as e:
            # 捕获所有验证失败的异常
            print(f"\n[Client]  警告：签名验证失败")
            print(f"[Client]  错误详情: {e}")
            print("[Client]  原因分析：公钥可能被篡改，或者签名不匹配。")
            print("[Client]  [安全策略] 系统拒绝建立不安全的连接，正在断开")
            client.close()
            return  # 这里的 return 非常关键，直接终止程序，不进行后续通信

        # 第三步：生成客户端 DH 参数并发送 (只有验签通过才会执行到这里)
        
        
        print("[Client]  3.生成客户端 DH 公私钥")
        dh_priv_b = number.getRandomRange(2, p - 1)
        dh_pub_B = pow(g, dh_priv_b, p)

        print("[Client]  4.发送 DH 公钥 B 给服务端")
        send_packet(client, json.dumps({'B': dh_pub_B}).encode('utf-8'))

        # 计算 AES 密钥
        shared_secret = pow(A, dh_priv_b, p)
        aes_key = SHA256.new(str(shared_secret).encode('utf-8')).digest()
        
        # 停止计时
        end_time = time.perf_counter()
        duration = end_time - start_time
        
        print(f"[Client]  密钥协商成功 AES Key (SHA256): {aes_key.hex()[:20]}...")
        print(f"[System]  握手耗时：{duration:.5f} 秒")

        
        # 第四步：聊天循环

        print("[Client]  可以开始聊天了  ")

        # 启动子线程专门负责接收消息
        def receive_loop():
            while True:
                try:
                    encrypted_packet = recv_packet(client)
                    if not encrypted_packet: break
                    
                    # 拆解 AES-GCM 数据包
                    nonce = encrypted_packet[:16]
                    tag = encrypted_packet[16:32]
                    ciphertext = encrypted_packet[32:]
                    
                    # 解密
                    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                    print(f"\n[Server]: {plaintext.decode('utf-8')}")
                except:
                    break
        
        threading.Thread(target=receive_loop, daemon=True).start()

        # 主线程负责发送消息
        while True:
            msg = input()
            if not msg: break
            
            cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
            send_packet(client, cipher.nonce + tag + ciphertext)

    except Exception as e:
        print(f"[Client] 运行异常: {e}")
    finally:
        client.close()

if __name__ == '__main__':
    start_client()