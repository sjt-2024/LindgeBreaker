import socket
import threading
import time
import tkinter as tk
from tkinter import Listbox, Scrollbar
import queue

class LBAdmin:
    """
    LBAdmin 类是 LindgeBreaker 应用程序的管理员核心类。
    主要功能包括：
    - 启动和停止接收广播消息。
    - 监控在线主机列表，并定期更新。
    - 向局域网内的所有设备发送广播消息。
    - 在关闭窗口时正确停止所有后台线程并退出应用程序。
    类属性：
    - root: Tkinter 根窗口对象。
    - start_button: 启动接收广播的按钮。
    - stop_button: 停止接收广播的按钮。
    - boom_button: 发送广播消息的按钮。
    - listbox: 显示在线主机列表的 Listbox 组件。
    - scrollbar: 与 listbox 关联的滚动条。
    - label: 显示在线主机数量的标签。
    - receiving: 布尔值，表示是否正在接收广播。
    - unique_clients: 字典，存储在线主机的 IP 地址和最后接收时间。
    - sock: 用于接收广播的 socket 对象。
    - thread: 接收广播的后台线程。
    - monitor_thread: 监控在线主机列表的后台线程。
    - queue: 用于线程间通信的队列。
    方法：
    - __init__(self, root): 初始化 LBAdmin 对象，设置 Tkinter 界面布局和组件。
    - start_receiving(self): 启动接收广播并启动两个线程。
    - stop_receiving(self): 停止接收广播并关闭套接字。
    - receive_broadcasts(self): 接收广播并记录客户端。
    - monitor_clients(self): 定期检查客户端列表，删除过期的客户端。
    - update_ui(self): 更新列表框和标签。
    - boom(self): 向局域网内的所有设备发送广播消息。
    - process_queue(self): 处理队列中的消息。
    - on_closing(self): 关闭窗口时停止接收广播并退出。
    """
    def __init__(self, root):
        self.root = root
        self.root.title("Broadcast Receiver")
        
        self.start_button = tk.Button(root, text="开始", command=self.start_receiving, width=10)
        self.start_button.grid(row=0, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(root, text="结束", command=self.stop_receiving, width=10)
        self.stop_button.grid(row=0, column=2, padx=10, pady=10)

        self.boom_button = tk.Button(root, text="Boom!", command=self.boom, width=10)
        self.boom_button.grid(row=0, column=1, padx=10, pady=10)

        # 设置列权重
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_columnconfigure(2, weight=1)

        
        self.listbox = Listbox(root, width=40, height=10)
        self.scrollbar = Scrollbar(root, orient="vertical", command=self.listbox.yview)
        self.listbox.config(yscrollcommand=self.scrollbar.set)
        self.listbox.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.scrollbar.grid(row=1, column=2, sticky="ns")
        
        self.label = tk.Label(root, text="在线主机: 0")
        self.label.grid(row=2, column=0, columnspan=2, padx=10, pady=10)
        
        self.receiving = False
        self.unique_clients = {}
        self.sock = None
        self.thread = None
        self.monitor_thread = None
        self.queue = queue.Queue()

        # 配置列和行的权重，使列表框能够扩展
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(1, weight=1)

        # 启动一个定期检查队列的线程
        self.root.after(100, self.process_queue)

        # 绑定窗口关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def start_receiving(self):
        # 启动接收广播并启动两个线程
        if self.thread and self.thread.is_alive():
            return
        self.receiving = True
        self.thread = threading.Thread(target=self.receive_broadcasts)
        self.thread.start()
        self.monitor_thread = threading.Thread(target=self.monitor_clients)
        self.monitor_thread.start()

    def stop_receiving(self):
        # 停止接收广播并关闭套接字
        self.receiving = False
        if self.sock:
            self.sock.close()
            self.sock = None

    def receive_broadcasts(self):
        # 接收广播并记录客户端
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', 39999))
            while self.receiving:
                try:
                    data, addr = self.sock.recvfrom(1024)
                    if data.decode() == "LB Running":
                        self.unique_clients[addr[0]] = time.time()
                        self.queue.put(("update_ui",))
                except socket.error as e:
                    if not self.receiving:
                        break
                    self.queue.put(f"Socket error: {e}\n")
        finally:
            if self.sock:
                self.sock.close()
                self.sock = None

    def monitor_clients(self):
        # 定期检查客户端列表，删除过期的客户端
        while self.receiving:
            current_time = time.time()
            clients_to_remove = [ip for ip, last_time in self.unique_clients.items() if current_time - last_time > 2]
            for ip in clients_to_remove:
                del self.unique_clients[ip]
            self.queue.put(("update_ui",))
            time.sleep(1)

    def update_ui(self):
        # 更新列表框和标签
        self.listbox.delete(0, tk.END)
        for ip, last_time in self.unique_clients.items():
            self.listbox.insert(tk.END, f"{ip} at {time.ctime(last_time)}")
        self.label.config(text=f"在线主机: {len(self.unique_clients)}")
        self.root.update_idletasks()
    
    def boom(self):
        # 向局域网内的所有设备发送广播
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto("Boom!".encode(), ('<broadcast>', 39999))
        sock.close()

    def process_queue(self):
        # 处理队列中的消息
        try:
            while True:
                message = self.queue.get_nowait()
                if message:
                    if message[0] == "update_ui":
                        self.update_ui()
                    else:
                        self.listbox.insert(tk.END, message)
        except queue.Empty:
            pass
        self.root.after(100, self.process_queue)

    def on_closing(self):
        # 关闭窗口时停止接收广播并退出
        self.stop_receiving()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = LBAdmin(root)
    root.mainloop()