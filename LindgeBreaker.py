'''
凌极爆破者/LindgeBreaker SJT 版权所有
本程序使用MPL2.0开源协议
程序说明:
    凌极爆破者/LindgeBreaker 是针对凌极机房控制系统受控端开发的爆破工具,可以让受控端HAPPY.
    程序开发环境:Python 3.12.2
'''
import ttkbootstrap as ttk
from ttkbootstrap.dialogs import Messagebox as msgbox
from tkinter import simpledialog as sd
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
    Methods:
    --------
    __init__(self, root):
        初始化方法，设置主窗口属性，读取进程列表，验证授权码，创建控件，并启动队列处理线程。
    center_window(self):
        将主窗口居中显示。
    process_status_queue(self):
        处理状态队列，将队列中的消息更新到状态栏。
    validate_auth_code(self):
        验证授权码，确保用户有权限运行程序。
    create_widgets(self):
        创建用户界面控件，包括按钮、状态栏和版权信息声明。
    update_status(self, message):
        更新状态栏，显示消息。
    processBreaker(self, process_names):
        进程爆破者，根据进程名列表终止指定进程。
    core(self, process_name):
        核心函数，持续运行进程爆破者，直到停止事件被触发。
    run_core(self):
        启动爆破线程，开始进程爆破。
    stop_core(self):
        停止爆破线程，结束进程爆破。
    clear_status(self):
        清除状态栏中的内容。
    on_closing(self):
        处理窗口关闭事件，停止爆破线程并等待所有线程退出。
    """
    def __init__(self, root):
        self.root = root
        self.root.title('LindgeBreaker')
        self.root.geometry('238x287')
        self.root.wm_resizable(0, 0)
        self.root.after(100, self.center_window)
        
        # 使用相对路径设置图标
        icon_path = os.path.join(current_directory, 'LindgeBreaker.ico')
        if os.path.exists(icon_path):
            self.root.iconbitmap(icon_path)
        else:
            logging.error(f'图标文件不存在: {icon_path}')
        
        # 读取进程列表
        if os.path.exists(process_path):
            try:
                with open(process_path, "rb") as f:
                    process_names = pkl.load(f)
                    self.process_names = process_names
            except Exception as e:
                logging.error(f"读取文件时发生错误: {e}")
                self.root.deiconify()  # 显示主窗口
                msgbox.show_error( f'进程列表读取错误: {e}')
                root.destroy()  # 关闭主窗口
        else:
            logging.error(f"进程列表不存在: {process_path}")
            self.root.deiconify()  # 显示主窗口
            msgbox.show_error(f'进程列表不存在: {process_path}')
            root.destroy()  # 关闭主窗口
        
        self.processed_processes = set() # 已处理的进程
        self.stop_event = threading.Event()  # 停止事件
        self.validate_auth_code()  # 验证授权码
        self.create_widgets()  # 创建控件
        self.status_queue = queue.Queue() # 创建队列
        self.status_lock = threading.Lock()  # 添加锁来保护对status_text的访问
        self.root.after(100, self.process_status_queue)  # 启动队列处理线程
    
    @staticmethod
    def errorHandle(func):  # 错误处理装饰器
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logging.error(f'函数 {func.__name__} 发生错误: {e}')
                root.deiconify()  # 显示主窗口
                msgbox.show_error(f'函数 {func.__name__} 发生错误: {e}')
        return wrapper

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
            logging.info(message)
        except Exception as e:
            logging.error(f'更新状态栏时发生错误: {e}')

    def processBreaker(self, process_names): # 进程爆破者
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
        self.status_text.insert('end', '\n已停止爆破...')  # 显示停止消息
        self.status_text.config(state='disabled')
    
    @errorHandle
    def clear_status(self): # 清除状态栏
        self.status_text.config(state='normal')
        self.status_text.delete('1.0', 'end')
        self.status_text.config(state='disabled')
    
    @errorHandle
    def on_closing(self):
        self.stop_core()  # 停止爆破线程
        for thread in threading.enumerate():  # 等待所有线程退出
            if thread != threading.main_thread():  # 忽略主线程
                thread.join()   
            self.root.after(0, self.root.destroy) 

if __name__ == '__main__':
    root = ttk.Window(themename='vapor') # 这主题嘎嘎好看
    root.withdraw()  # 在验证授权码之前隐藏主窗口
    app = LindgeBreaker(root)
    root.mainloop()