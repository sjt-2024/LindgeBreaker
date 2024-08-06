import pickle
import tkinter as tk
from tkinter.filedialog import askopenfilename
from tkinter import messagebox as msgbox

def read_pkl(): # 选择pkl文件
    global open_file
    global current_file_label
    open_file = askopenfilename(title="请选择文件",filetypes=[("pkl存档","*.pkl")])
    if open_file:
        current_file_label.config(text=f"当前文件: {open_file}")
    else:
        current_file_label.config(text="当前文件: 未选择")

def dump_pkl(): # 保存pkl文件
    global open_file
    global dump_text
    try:
        dump_data = dump_text.get(1.0, tk.END).strip()
        if dump_data == "":
            msgbox.showerror("错误", "保存内容不能为空")
            return
        else:
            with open(open_file, 'wb') as f:
                pickle.dump(dump_data, f)
                msgbox.showinfo("提示", "保存成功")
    except Exception as e:
        msgbox.showerror("错误", f"错误:{str(e)}")
        
def load_pkl(): # 读取pkl文件
    global open_file
    global load_text
    try:
        with open(open_file, 'rb') as f:
            load_data = pickle.load(f)
            load_text.delete(1.0, tk.END)
            load_text.insert(tk.END, load_data)
    except NameError:
        msgbox.showerror("错误", "请先选择文件")
    except Exception as e:
        msgbox.showerror("错误", f"错误:{str(e)}")
        
root = tk.Tk()
root.title("pklTool")

# 使用 grid 布局
dump_text = tk.Text(root, width=50, height=10)
dump_text.grid(row=3, column=0, sticky="nsew")

load_text = tk.Text(root, width=50, height=10)
load_text.grid(row=3, column=1, sticky="nsew")

# 添加滚动条
dump_scrollbar = tk.Scrollbar(root, command=dump_text.yview)
dump_scrollbar.grid(row=3, column=0, sticky="nse")
dump_text.config(yscrollcommand=dump_scrollbar.set)

load_scrollbar = tk.Scrollbar(root, command=load_text.yview)
load_scrollbar.grid(row=3, column=1, sticky="nse")
load_text.config(yscrollcommand=load_scrollbar.set)

read_btn = tk.Button(root, text="选择pkl文件", command=read_pkl)
read_btn.grid(row=0, column=0, columnspan=2)

dump_btn = tk.Button(root, text="保存pkl文件", command=dump_pkl)
dump_btn.grid(row=2, column=0)

load_btn = tk.Button(root, text="读取pkl文件", command=load_pkl)
load_btn.grid(row=2, column=1)

# 添加标签显示当前选择的文件名
current_file_label = tk.Label(root, text="当前文件: 未选择")
current_file_label.grid(row=0, column=1, columnspan=2)

# 设置列和行的权重，使Text组件能够随窗口大小变化
root.grid_columnconfigure(0, weight=1)
root.grid_columnconfigure(1, weight=1)
root.grid_rowconfigure(3, weight=1)

root.mainloop()
