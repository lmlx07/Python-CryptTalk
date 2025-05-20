import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from time import localtime, strftime
import socket
import threading
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import sys
import os

frames = []
outputs = []  # 设置一个output，将scroll附加进去，从而修改文本内容
inputs = []
text_ip = []  # 锁定ip1234
text_port = []  # 锁定端口号
entry_box = []  # 5个输入框
text_state = []  # 锁定启动文本
button_control = []  # 启动开关
new_tag_count = 0  # 每一条消息分割tag
mode = ''  # 当前模式
send_message = ''  # 要发送的消息
close_connect = False  # 不开启连接


# ================== 服务端线程 ==================
class RemoteServer(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.rsa_key = RSA.generate(2048)
        self.clients = []
        self.lock = threading.Lock()
        self.running = True
        self.host = host
        self.port = port

    def run(self):
        global close_connect
        # 输入监听线程
        input_thread = threading.Thread(target=self.server_input_handler)
        input_thread.daemon = True
        input_thread.start()

        # 主服务线程
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(5)
            sender = '我'
            message = "服务启动"
            receive_message(message, sender)
            message = "服务IP地址 : " + self.host + " 端口号 : " + str(self.port)
            receive_message(message, sender)
            # 改变启动图标
            if mode == 'server':
                text_state[0].set("已启动")
                text_state[1].config(fg="green")
                button_control[0].config(text="关闭", command=close_connect_event)
            # print(f"Server listening on {host}:{port}")

            while self.running:
                try:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(conn, addr)
                    )
                    client_thread.start()
                except OSError:
                    break  # 服务器正常关闭

    def handle_client(self, conn, addr):
        try:
            # 密钥交换阶段
            pub_key = self.rsa_key.publickey().export_key()
            conn.sendall(len(pub_key).to_bytes(4, 'big'))
            conn.sendall(pub_key)

            encrypted_des_key = conn.recv(1024)
            cipher_rsa = PKCS1_OAEP.new(self.rsa_key)
            des_key = cipher_rsa.decrypt(encrypted_des_key)
            cipher_des = DES.new(des_key, DES.MODE_ECB)

            with self.lock:
                self.clients.append((conn, cipher_des, addr))

            sender = addr
            message = "进入房间"
            receive_message(message, sender)
            # print(f"New connection from {addr}")
            self.broadcast(f"欢迎{addr}进入房间")

            # 消息接收循环
            while self.running:
                try:
                    raw_len = conn.recv(4)
                    if not raw_len:
                        break
                    msg_len = int.from_bytes(raw_len, 'big')

                    encrypted_msg = b''
                    while len(encrypted_msg) < msg_len:
                        chunk = conn.recv(min(4096, msg_len - len(encrypted_msg)))
                        if not chunk:
                            break
                        encrypted_msg += chunk

                    # 消息解密验证
                    decrypted = unpad(cipher_des.decrypt(encrypted_msg), DES.block_size)
                    received_hash = decrypted[:16]
                    message = decrypted[16:]

                    if MD5.new(message).digest() != received_hash:
                        print(f"Invalid message from {addr}")
                        continue

                    msg_str = message.decode(errors='replace')
                    sender = addr
                    receive_message(msg_str, sender)
                    # print(f"[{addr}] {msg_str}")
                    self.broadcast(f"[{addr}] {msg_str}", exclude=conn)

                except (ConnectionResetError, BrokenPipeError):
                    break
                except Exception as e:
                    print(f"Error with {addr}: {str(e)}")
                    break

        finally:
            self.remove_client(conn)
            conn.close()
            sender = addr
            message = "离开房间"
            receive_message(message, sender)
            # print(f"Connection closed: {addr}")
            self.broadcast(f"{addr}离开了房间")

    def broadcast(self, message, exclude=None):
        """广播消息给所有客户端"""
        if not message:
            return

        encoded_msg = message.encode()
        h = MD5.new(encoded_msg)
        full_msg = h.digest() + encoded_msg

        with self.lock:
            for client in self.clients.copy():
                conn, cipher, addr = client
                if conn == exclude:
                    continue
                try:
                    encrypted = cipher.encrypt(pad(full_msg, DES.block_size))
                    conn.sendall(len(encrypted).to_bytes(4, 'big'))
                    conn.sendall(encrypted)
                except (ConnectionResetError, BrokenPipeError):
                    self.remove_client(conn)
                except Exception as e:
                    print(f"Send error to {addr}: {str(e)}")
                    self.remove_client(conn)

    def remove_client(self, conn):
        """移除断开连接的客户端"""
        with self.lock:
            for i, client in enumerate(self.clients):
                if client[0] == conn:
                    del self.clients[i]
                    break

    def server_input_handler(self):
        global send_message
        global mode
        """服务端控制台输入处理"""
        while self.running:
            try:
                if send_message != '':
                    self.broadcast(send_message)
                    send_message = ''
                if mode == '':
                    self.shutdown()
                    break
                if close_connect:
                    self.shutdown()
                    break
                # msg = input()
                # if msg.lower() == '/quit':
                #     self.shutdown()
                #     break
                # self.broadcast(msg)
            except KeyboardInterrupt:
                self.shutdown()
                break

    def shutdown(self):
        global close_connect
        if mode == 'server':
            text_state[0].set("未启动")
            text_state[1].config(fg="red")
            button_control[0].config(text="启动", command=connect_server)
        """安全关闭服务器"""
        print("Shutting down server...")
        self.running = False
        close_connect = False
        with self.lock:
            for client in self.clients:
                try:
                    client[0].close()
                except:
                    pass
        sys.exit(0)


# ================== 客户端线程 ==================

class RemoteClient(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.des_key = get_random_bytes(8)
        self.cipher_des = DES.new(self.des_key, DES.MODE_ECB)
        self.running = True
        self.sock = None
        self.host = host
        self.port = port

    def run(self):
        global send_message
        global close_connect
        global mode
        try:
            self.sock = socket.create_connection((self.host, self.port))  # 删除生周期 timeout=10
            sender = '我'
            message = "连接到服务器"
            receive_message(message, sender)
            message = "已进入('" + self.host + "', " + str(self.port) + ")的房间"
            receive_message(message, sender)
            # 改变启动图标
            if mode == 'client':
                text_state[0].set("已连接")
                text_state[1].config(fg="green")
                button_control[0].config(text="关闭", command=close_connect_event)
            # print(f"Connected to {host}:{port}")

            # 密钥交换
            pub_key_len = int.from_bytes(self.sock.recv(4), 'big')
            pub_key = RSA.import_key(self.sock.recv(pub_key_len))
            cipher_rsa = PKCS1_OAEP.new(pub_key)
            self.sock.sendall(cipher_rsa.encrypt(self.des_key))

            # 启动接收线程
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()

            # 消息输入循环
            while self.running:
                try:
                    if send_message != '':
                        self.send_message(send_message)
                        send_message = ''
                    if close_connect:
                        self.disconnect()
                        break
                    if mode == '':
                        self.disconnect()
                        break
                    # msg = input()
                    # if msg.lower() == '/exit':
                    #     break
                    # self.send_message(msg)
                except KeyboardInterrupt:
                    break

        except socket.timeout:
            print("Connection timed out")
        except ConnectionRefusedError:
            print("Connection refused")
        except Exception as e:
            print(f"Connection error: {str(e)}")
        finally:
            self.disconnect()

    def send_message(self, message):
        """加密发送消息"""
        try:
            encoded = message.encode()
            h = MD5.new(encoded)
            full_msg = h.digest() + encoded
            encrypted = self.cipher_des.encrypt(pad(full_msg, DES.block_size))
            self.sock.sendall(len(encrypted).to_bytes(4, 'big'))
            self.sock.sendall(encrypted)
        except Exception as e:
            print(f"Send error: {str(e)}")
            self.disconnect()

    def receive_messages(self):
        """消息接收循环"""
        while self.running:
            try:
                raw_len = self.sock.recv(4)
                if not raw_len:
                    break
                msg_len = int.from_bytes(raw_len, 'big')

                encrypted = b''
                while len(encrypted) < msg_len:
                    chunk = self.sock.recv(min(4096, msg_len - len(encrypted)))
                    if not chunk:
                        break
                    encrypted += chunk

                decrypted = unpad(self.cipher_des.decrypt(encrypted), DES.block_size)
                received_hash = decrypted[:16]
                message = decrypted[16:]

                if MD5.new(message).digest() != received_hash:
                    print("Received invalid message")
                    continue

                sender = "房主"
                # 改个名字和这里的变量做一下区分
                message1 = message.decode(errors='replace')
                if message1[0] == '[':
                    sender = message1.split("]")[0]
                    sender = sender[1:]
                    message1 = message1.split("]")[1]
                receive_message(message1, sender)
                # print(f"\n[Remote] {message.decode(errors='replace')}")
                # print("> ", end="", flush=True)

            except (ConnectionResetError, BrokenPipeError):
                sender = "我"
                # 改个名字和这里的变量做一下区分
                message1 = "丢失连接"
                receive_message(message1, sender)
                message1 = "已离开房间"
                receive_message(message1, sender)
                # print("\nConnection lost")
                break
            except Exception as e:
                # print(f"\nReceive error: {str(e)}")
                break

    def disconnect(self):
        global close_connect
        if mode == 'client':
            text_state[0].set("未连接")
            text_state[1].config(fg="red")
            button_control[0].config(text="连接", command=connect_client)
        """安全断开连接"""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        print("Disconnected")
        close_connect = False


# ================== 网络服务启动 ==================

def Start_Server(host, port):
    # host, port = Config.get_server_address()  # 改成调用输入内容
    server = RemoteServer(host, port)
    try:
        server.daemon = True  # 设置守护线程
        server.start()
    except KeyboardInterrupt:
        server.shutdown()


def Start_Client(host, port):
    # host, port = Config.get_client_address()      # 改成调用输入内容
    client = RemoteClient(host, port)
    client.daemon = True
    client.start()


def get_local_ipv4():
    """获取ip地址"""
    ip_address = ''
    # 获取IP地址
    ipconfig_process = os.popen('ipconfig')
    ipconfig_output = ipconfig_process.read()
    ipconfig_process.close()
    lines = ipconfig_output.split('\n')
    for i in range(len(lines)):
        if 'WLAN' in lines[i]:
            # print(lines[i + 4].split(': ')[-1])
            ip_address = lines[i + 4].split(': ')[-1]
        if '以太网' in lines[i]:
            # print(lines[i + 4].split(': ')[-1])
            ip_address = lines[i + 4].split(': ')[-1]
    return ip_address


# ================== 图形化界面搭建 ==================

def Server_Panel():
    global mode
    mode = 'server'
    Setup_Board()


def Client_Panel():
    global mode
    mode = 'client'
    Setup_Board()


def Setup_Board():
    global mode
    global close_connect
    close_connect = False
    # 销毁原组件
    remove_all_frames()

    # 生成文本框
    back_frame = tk.Frame(root)
    left1_frame = tk.Frame(back_frame)
    right1_frame = tk.Frame(back_frame)
    back_frame.pack(side="right", fill="y", expand=False, ipadx=10)
    output_text = ScrolledText(back_frame, height=30, width=50, state="disable", font="微软雅黑")
    output_text.pack(pady=10)
    input_text = tk.Text(back_frame, height=5, width=52, font="微软雅黑")
    input_text.pack(pady=0)
    input_text.bind("<Return>", enter_input)
    input_text.bind("<KP_Enter>", enter_input)
    input_text.bind("<Escape>", esc_button)  # 帮忙绑定退出键
    inputs.append(input_text)
    outputs.append(output_text)
    frames.append(back_frame)

    # 生成登录界面
    logon_frame = tk.Frame(root)
    logon_frame.pack(side="left", fill="y", expand=False, ipadx=10, pady=10)
    # 输入ip
    ip_label = tk.Label(logon_frame, text="IP地址", font="微软雅黑")
    ip_label.pack()
    logon_level_frame = tk.Frame(logon_frame)
    logon_level_frame.pack(fill="y", expand=False)
    entry_var1 = tk.StringVar()
    ip1_entry = tk.Entry(logon_level_frame, width=4, textvariable=entry_var1, font="微软雅黑")
    ip1_entry.pack(side="left")
    ipp_label = tk.Label(logon_level_frame, text=".", font="微软雅黑")
    ipp_label.pack(side="left")
    entry_var2 = tk.StringVar()
    ip2_entry = tk.Entry(logon_level_frame, width=4, textvariable=entry_var2, font="微软雅黑")
    ip2_entry.pack(side="left")
    ipp_label = tk.Label(logon_level_frame, text=".", font="微软雅黑")
    ipp_label.pack(side="left")
    entry_var3 = tk.StringVar()
    ip3_entry = tk.Entry(logon_level_frame, width=4, textvariable=entry_var3, font="微软雅黑")
    ip3_entry.pack(side="left")
    ipp_label = tk.Label(logon_level_frame, text=".", font="微软雅黑")
    ipp_label.pack(side="left")
    entry_var4 = tk.StringVar()
    ip4_entry = tk.Entry(logon_level_frame, width=3, textvariable=entry_var4, font="微软雅黑")
    ip4_entry.pack(side="left")
    # 绑定输入事件
    ip1_entry.bind("<Return>", next_entry)  # 绑定回车事件
    ip1_entry.bind("<KP_Enter>", next_entry)  # 绑定数字键盘的回车事件
    ip1_entry.bind("<Key-.>", next_entry)  # 绑定.事件
    ip2_entry.bind("<Return>", next_entry)
    ip2_entry.bind("<KP_Enter>", next_entry)
    ip2_entry.bind("<Key-.>", next_entry)
    ip3_entry.bind("<Return>", next_entry)
    ip3_entry.bind("<KP_Enter>", next_entry)
    ip3_entry.bind("<Key-.>", next_entry)
    ip4_entry.bind("<Return>", next_entry)
    ip4_entry.bind("<KP_Enter>", next_entry)
    ip4_entry.bind("<Key-.>", next_entry_point)
    # 服务端输入默认值
    if mode == 'server':
        myip = []
        for line in get_local_ipv4().split('.'):
            myip.append(line)
        entry_var1.set(myip[0])
        entry_var2.set(myip[1])
        entry_var3.set(myip[2])
        entry_var4.set(myip[3])
    text_ip.append(entry_var1)
    text_ip.append(entry_var2)
    text_ip.append(entry_var3)
    text_ip.append(entry_var4)
    entry_box.append(ip1_entry)
    entry_box.append(ip2_entry)
    entry_box.append(ip3_entry)
    entry_box.append(ip4_entry)
    # 端口号
    port_label = tk.Label(logon_frame, text="端口号", font="微软雅黑")
    port_label.pack()
    entry_var5 = tk.StringVar()
    port_entry = tk.Entry(logon_frame, textvariable=entry_var5, font="微软雅黑")
    port_entry.pack()
    port_entry.bind("<Return>", next_entry)
    port_entry.bind("<KP_Enter>", next_entry)
    if mode == 'server':
        entry_var5.set("65432")
    text_port.append(entry_var5)
    entry_box.append(port_entry)
    # 显示当前链接状态
    logon_level1_frame = tk.Frame(logon_frame)
    logon_level1_frame.pack(fill="y", expand=False)
    logon_level2_frame = tk.Frame(logon_frame)
    logon_level2_frame.pack(fill="y", expand=False)
    logon_left_frame = tk.Frame(logon_level1_frame)
    logon_left_frame.pack(side="left", fill="y", expand=False, ipadx=10, pady=10)
    logon_right_frame = tk.Frame(logon_level1_frame)
    logon_right_frame.pack(side="right", fill="y", expand=False, ipadx=10, pady=10)
    state1_label = tk.Label(logon_left_frame, text="当前状态：", font="微软雅黑")
    state1_label.pack()
    text_content = tk.StringVar()
    text_content.set("已连接")
    state_label = tk.Label(logon_right_frame, textvariable=text_content, fg="green", font="微软雅黑")
    state_label.pack()
    text_state.append(text_content)  # 存两个一个是文本，第二个是状态
    text_state.append(state_label)
    if mode == 'server':
        text_content.set("未启动")
        state_label.config(fg="red")
    elif mode == "client":
        text_content.set("未连接")
        state_label.config(fg="red")

    # 链接按钮
    run_button = tk.Button(logon_level2_frame, text="启动", width=18, font="微软雅黑")
    run_button.pack(pady=0)
    frames.append(logon_frame)
    if mode == 'server':
        run_button.config(text="启动", command=connect_server)
    elif mode == 'client':
        run_button.config(text="连接", command=connect_client)
    button_control.append(run_button)

    # 生成按钮
    left1_frame.pack(side="left", fill="y", expand=True, ipadx=20)
    right1_frame.pack(side="right", fill="y", expand=False, ipadx=20)
    left2_frame = tk.Frame(right1_frame)
    right2_frame = tk.Frame(right1_frame)
    right2_frame.pack(side="right", fill="y", expand=True, ipadx=10)
    left2_frame.pack(side="right", fill="y", expand=True, ipadx=10)
    run_button = tk.Button(right2_frame, text="发送(Enter)", command=append_message, width=10, font="微软雅黑")
    run_button.pack(pady=20)
    run_button = tk.Button(left2_frame, text="返回(Esc)", command=Back_Board, width=10, font="微软雅黑")
    run_button.pack(pady=21.2)  # 校准


def Back_Board():
    global mode
    mode = ''
    # 声明框架
    left_frame = tk.Frame(root)
    right_frame = tk.Frame(root)

    # 销毁原组件
    remove_all_frames()

    # 生成组件
    left_frame.pack(side="left", fill="y", expand=True, ipadx=40)
    right_frame.pack(side="right", fill="y", expand=True, ipadx=40)
    frames.append(left_frame)
    frames.append(right_frame)

    Server_button = tk.Button(left_frame, text="服务端", command=Server_Panel, font="微软雅黑")
    Server_button.pack(pady=40)
    Client_button = tk.Button(right_frame, text="客户端", command=Client_Panel, font="微软雅黑")
    Client_button.pack(pady=40)


def remove_all_frames():
    """删除所有Frame"""
    for frame in frames:
        frame.destroy()
    frames.clear()  # 清空列表
    """删除output"""
    outputs.clear()  # 清空列表
    """删除input"""
    inputs.clear()  # 清空列表

    text_ip.clear()
    text_port.clear()
    text_state.clear()
    button_control.clear()
    entry_box.clear()


def close_connect_event():
    global close_connect
    close_connect = True  # 关闭连接


def esc_button(event):
    Back_Board()


def enter_input(event):
    """发送回车事件"""
    append_message()
    return "break"


def next_entry(event):
    """重写回车事件"""
    current_entry = event.widget
    if current_entry in entry_box:
        index = entry_box.index(current_entry)
        if index < len(entry_box) - 1:
            next_entry = entry_box[index + 1]
        else:
            next_entry = entry_box[0]
        next_entry.focus()
    if event.char not in '0123456789':  # 只允许数字
        return "break"  # 阻止非法字符的输入


def next_entry_point(event):
    """重写回车事件"""
    if event.char not in '0123456789':  # 只允许数字
        return "break"  # 阻止非法字符的输入


# ================== 服务启动接口 ==================

def connect_server():
    ip = ''
    port = ''
    for text in text_ip:
        ip += text.get() + '.'
    ip = ip[:-1]  # 切掉最后一个字符
    for text in text_port:
        port = text.get()
    port = int(port)
    Start_Server(ip, port)


def connect_client():
    ip = ''
    port = ''
    for text in text_ip:
        ip += text.get() + '.'
    ip = ip[:-1]  # 切掉最后一个字符
    for text in text_port:
        port = text.get()
    port = int(port)
    Start_Client(ip, port)


# ================== 聊天页面操作 ==================

def append_message():
    """添加信息到聊天区"""
    global new_tag_count
    global send_message
    sender = "我"
    message = ''
    new_tag_count += 1
    new_tag = 'time' + str(new_tag_count)
    for input1 in inputs:
        message = input1.get(0.0, tk.END)
        message = message.lstrip('\n')  # 删掉第一个换行符
        while message.endswith('\n'):  # 删掉末尾的换行和空格
            message = message.rstrip('\n')
        while message.endswith(' '):
            message = message.rstrip(' ')
        input1.delete("1.0", tk.END)

    if message == "":
        return

    # 获得当前时间
    send_time = strftime('%Y-%m-%d %H:%M:%S', localtime())
    sender_info = '%s: %s\n' % (sender, send_time)
    for output in outputs:
        output.config(state="normal")
        output.insert(tk.END, sender_info, new_tag)
        output.insert(tk.END, ' ' + message + '\n\n', 'content')
        output.tag_config(new_tag, foreground='green')
        output.tag_config('content', foreground='black')
        output.config(state="disable")
    send_message = message


def receive_message(message, sender):
    global new_tag_count
    new_tag_count += 1
    new_tag = 'time' + str(new_tag_count)
    send_time = strftime('%Y-%m-%d %H:%M:%S', localtime())
    sender_info = '%s: %s\n' % (sender, send_time)
    for output in outputs:
        output.config(state="normal")
        output.insert(tk.END, sender_info, new_tag)
        output.insert(tk.END, ' ' + message + '\n\n', 'content')
        if sender == '我':
            output.tag_config(new_tag, foreground='green')
        else:
            output.tag_config(new_tag, foreground='blue')
        output.tag_config('content', foreground='black')
        output.config(state="disable")


# ================== 主程序 ==================
if __name__ == "__main__":
    root = tk.Tk()
    root.title("CryptTalk")
    root.resizable(False, False)
    Back_Board()
    root.mainloop()
