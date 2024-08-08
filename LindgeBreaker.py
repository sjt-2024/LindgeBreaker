'''
凌极爆破者/LindgeBreaker SJT 版权所有
本程序使用MPL2.0开源协议
程序说明:
    凌极爆破者/LindgeBreaker 是针对凌极机房控制系统受控端开发的爆破工具,可以让受控端HAPPY.
    为了防止本程序大规模扩散,管理员可以紧急爆破客户端.
    程序开发环境:Python 3.12.2
'''
import ttkbootstrap as ttk
from ttkbootstrap.dialogs import Messagebox as msgbox
from tkinter import simpledialog as sd
from subprocess import run
import time
import threading
import psutil
import hashlib
import logging
import tkinter as tk
import os
import sys
import queue
import pickle as pkl
import socket

# 处理sys.path
# 获取当前文件的绝对路径
current_file_path = os.path.abspath(__file__)
# 获取当前文件所在的目录
current_directory = os.path.dirname(current_file_path)
# 当前文件所在的目录如果不在sys.path中，就添加到sys.path
if current_directory not in sys.path:
    sys.path.append(current_directory)

# 处理日志
log_file_path = os.path.join(current_directory, 'LindgeBreaker.log')
logging.basicConfig(filename=log_file_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 定义一些常量
process_path = os.path.join(current_directory, 'process.pkl') # 务必建一个pkl文件!里面用列表存进程列表!
auth_path = os.path.join(current_directory, 'auth.txt')


class LindgeBreaker:
    """
    凌极爆破者核心类，负责管理应用程序的主要功能和用户界面。

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
        self.center_window()
        self.root.title('LindgeBreaker')
        self.root.geometry('238x287')
        self.root.wm_resizable(0, 0)
        
        # 读取进程列表
        if os.path.exists(process_path):
            try:
                with open(process_path, "rb") as f:
                    process_names = pkl.load(f)
                    self.process_names = process_names
            except Exception as e:
                logging.error(f"进程列表读取错误: {e}")
                self.root.deiconify()  # 显示主窗口
                msgbox.show_error( f'进程列表读取错误: {e}','进程列表读取错误')
                root.destroy()  # 关闭主窗口
        else:
            logging.error(f"进程列表不存在: {process_path}")
            self.root.deiconify()  # 显示主窗口
            msgbox.show_error(f'进程列表不存在: {process_path}','进程列表不存在')
            root.destroy()  # 关闭主窗口
            return
            
        self.validate_auth_code()  # 验证授权码
        self.processed_processes = set() # 已处理的进程
        self.stop_event = threading.Event()  # 停止事件
        self.create_widgets()  # 创建控件
        self.status_queue = queue.Queue() # 创建队列
        self.status_lock = threading.Lock()  # 添加锁来保护对status_text的访问
        self.root.after(100, self.process_status_queue)  # 启动队列处理线程

        # 启动广播消息线程
        threading.Thread(target=self.broadcast_message, daemon=True).start()
        
        # 启动监听"Boom!"消息的线程
        threading.Thread(target=self.listen_for_boom, daemon=True).start()
    
    @staticmethod
    def errorHandle(func):  # 错误处理装饰器
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logging.error(f'函数 {func.__name__} 发生错误: {e}')
                root.deiconify()  # 显示主窗口
                msgbox.show_error(f'函数 {func.__name__} 发生错误: {e}','函数错误')
        return wrapper

    @errorHandle
    def listen_for_boom(self):
        """
        监听局域网内是否有人发送"Boom!"消息,有就调用boom方法。
        """
        SERVER_ADDRESS = ('', 39999)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # 重用地址
            sock.bind(SERVER_ADDRESS)
            while not self.stop_event.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    if data.decode() == "Boom!":
                        self.boom()
                        break
                except Exception as e:
                    logging.error(f'监听消息时发生错误: {e}')
                    break

    @errorHandle
    def center_window(self):  # 窗口居中
        self.root.update_idletasks()  # 确保窗口的所有任务都已完成
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        window_width = self.root.winfo_width()
        window_height = self.root.winfo_height()
        x_coordinate = (screen_width / 2) - (window_width / 2)
        y_coordinate = (screen_height / 2) - (window_height / 2)
        self.root.geometry(f'{window_width}x{window_height}+{int(x_coordinate)}+{int(y_coordinate)}')

    @errorHandle
    def process_status_queue(self): # 处理状态队列
        while not self.status_queue.empty():
            message = self.status_queue.get()
            self.update_status(message)
        self.root.after(100, self.process_status_queue)

    def validate_auth_code(self):  # 验证授权码
        auth_code = "43992ae17e637c8de2de1827e43ad146eccd161e2ca16748b7118df1578bc352" # 授权码
        auth_string = "sjtauthyou"  # 授权文件中的目标字符串
        # 我相信sha256加密算法是安全的，而且我也不想把密码泄露.但授权文件,我懒得写hash值.
        if os.path.exists(auth_path):
            try:
                with open(auth_path, 'rt', encoding='utf-8') as file:
                    for line in file:
                        if auth_string in line:
                            self.root.deiconify()  # 显示主窗口
                            msgbox.show_info('授权成功', '授权成功', parent=self.root)  # 设置父窗口
                            break
            except tk.TclError:
                pass  # 捕获并忽略主窗口关闭时的异常
            except Exception as e:
                logging.error(f'验证授权码时发生错误: {e}')
                self.root.withdraw()  # 隐藏主窗口
                self.root.destroy()  # 关闭主窗口
        else:
            try:
                auth_type = sd.askstring('授权码', '请输入授权码', show='*')
                if auth_type is None:  # 用户关闭了输入窗口
                    self.root.destroy()  # 关闭主窗口
                    return
                else:
                    hashed_auth_type = hashlib.sha256(auth_type.encode()).hexdigest()
                if hashed_auth_type == auth_code:
                    self.root.deiconify()  # 显示主窗口
                    msgbox.show_info('授权成功', '授权成功', parent=self.root)  # 设置父窗口
                else:
                    self.root.deiconify()  # 显示主窗口
                    msgbox.show_error('授权失败,程序退出', '授权失败', parent=self.root)  # 设置父窗口
                    self.root.destroy()  # 关闭主窗口
            except tk.TclError:
                pass  # 捕获并忽略主窗口关闭时的异常
            except Exception as e:
                logging.error(f'验证授权码时发生错误: {e}')
                self.root.withdraw()  # 隐藏主窗口
                self.root.destroy()  # 关闭主窗口

    def create_widgets(self): # 创建控件
        try:
            # 一堆按钮
            self.run_btn = ttk.Button(self.root, text='爆破', command=self.run_core)
            self.run_btn.grid(row=0, column=0, padx=10, pady=10)
            self.stop_btn = ttk.Button(self.root, text='停止', command=self.stop_core)
            self.stop_btn.grid(row=0, column=1, padx=10, pady=10)
            self.clear_btn = ttk.Button(self.root, text='清除', command=self.clear_status)
            self.clear_btn.grid(row=0, column=2, padx=10, pady=10)
            # 状态栏
            self.status_text = ttk.Text(self.root, height=10, width=30)
            self.status_text.grid(row=1, column=0, columnspan=3, pady=10)
            self.status_text.config(state='disabled')
            # 状态栏滚动条
            self.scrollbar = ttk.Scrollbar(self.root, command=self.status_text.yview)
            self.scrollbar.grid(row=1, column=3, sticky='ns')
            self.status_text.config(yscrollcommand=self.scrollbar.set)
            # 版权信息声明
            ttk.Label(self.root, text='LindgeBreaker · SJT 版权所有').grid(row=2, column=0, columnspan=3, pady=10)
            # 窗口关闭事件
            self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        except tk.TclError:
            pass  # 捕获并忽略主窗口关闭时的异常
        except Exception as e:
            logging.error(f'创建控件时发生错误: {e}')

    def update_status(self, message): # 更新状态栏
        try:
            with self.status_lock:  # 使用锁来保护对status_text的访问
                self.status_text.config(state='normal')
                self.status_text.insert('end', message)
                self.status_text.config(state='disabled')
                self.status_text.see('end')
        except Exception as e:
            logging.error(f'更新状态栏时发生错误: {e}')

    def processBreaker(self, process_names): #进程杀手
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'] in process_names and proc.info['pid'] not in self.processed_processes:
                try:
                    proc.kill()
                    self.processed_processes.add(proc.info['pid'])
                    self.status_queue.put(f'\n进程{proc.info["name"]}爆破成功')
                    logging.info(f'进程{proc.info["name"]}爆破成功')
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    self.status_queue.put(f'\n进程{proc.info["name"]}爆破失败: {e}')
                    logging.error(f'进程{proc.info["name"]}爆破失败: {e}')
                except Exception as e:
                    self.status_queue.put(f'\n未知爆破错误: {e}')
                    logging.error(f'未知爆破错误: {e}')

    def core(self, process_name): # 核心函数
        exception_handled = False  # 异常处理标志
        while not self.stop_event.is_set():
            try:
                self.processBreaker(process_name)
            except Exception as e:
                if not exception_handled:
                    self.update_status(f'\n核心函数异常: {e}')
                    logging.error(f'核心函数异常: {e}')
                    exception_handled = True
            time.sleep(1)

    @errorHandle
    def run_core(self): # 启动爆破线程
        self.stop_event.clear()
        threading.Thread(target=self.core, args=(self.process_names,)).start()
        self.status_text.config(state='normal')
        self.status_text.delete('1.0', 'end')
        self.status_text.insert('end', '放置炸药,开始爆破...')
        self.status_text.config(state='disabled')
    
    @errorHandle
    def stop_core(self): # 停止爆破线程
        self.stop_event.set()  # 设置停止事件
        self.status_text.config(state='normal')
        self.status_text.insert('end', '\n已停止爆破...')
        self.status_text.config(state='disabled')
    
    @errorHandle
    def clear_status(self): # 清除状态栏
        self.status_text.config(state='normal')
        self.status_text.delete('1.0', 'end')
        self.status_text.config(state='disabled')
    
    @errorHandle
    def on_closing(self):
        self.stop_core()  # 停止爆破线程
        self.stop_event.set()  # 设置停止事件
        self.root.destroy()  # 立即关闭主窗口
        
        # 在关闭主窗口后，再优雅地终止后台线程
        for thread in threading.enumerate():
            if thread != threading.main_thread():  # 忽略主线程
                thread.join(timeout=1)  # 等待子线程结束，但设置超时时间

    @errorHandle
    def broadcast_message(self): #在39999端口广播"LB Running"消息。
        SERVER_ADDRESS = ('', 39999)
        BROADCAST_MESSAGE = "LB Running"

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # 重用地址
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)  # 启用广播功能
            while not self.stop_event.is_set():
                try:
                    sock.sendto(BROADCAST_MESSAGE.encode(), ('<broadcast>', 39999))
                    time.sleep(1)  # 每秒广播一次
                except Exception as e:
                    logging.error(f'广播消息时发生错误: {e}')
                    break

    @errorHandle
    def boom(self):
        # 管理员指令自毁
        logging.warning('程序收到管理员的指令,开始自毁')
        
        # 获取当前运行的 .exe 文件路径
        exe_path = os.path.realpath(sys.argv[0])
        dir_name = os.path.dirname(exe_path)
        internal_dir = os.path.join(dir_name, '_internal')
        
        # 目标文件名（假设是解释器或 DLL 文件）
        target_file = 'python312.dll'  # Python 3.12.2 解释器文件名
        target_path = os.path.join(internal_dir, target_file)
        
        # 新文件名
        new_file_name = 'python312..dll'
        new_file_path = os.path.join(internal_dir, new_file_name)
        
        # 启动重命名线程
        rename_thread = threading.Thread(target=self.rename_file, args=(target_path, new_file_path))
        rename_thread.start()
        
        # 关闭主窗口
        self.root.destroy()
        
        # 等待重命名线程完成
        rename_thread.join(timeout=1)

    @errorHandle
    def rename_file(self, old_file_path, new_file_path):
        try:
            if os.path.exists(old_file_path):
                os.rename(old_file_path, new_file_path)
                logging.warning(f'自毁完毕')
            else:
                logging.error(f'自毁失败')
        except Exception as e:
            logging.error(f'自毁错误: {e}')

if __name__ == '__main__':
    root = ttk.Window(themename='vapor')  # 这主题嘎嘎好看
    root.withdraw()  # 在验证授权码之前隐藏主窗口
    app = LindgeBreaker(root)
    root.mainloop()