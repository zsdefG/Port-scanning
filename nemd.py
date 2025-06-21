import socket 
import threading
import queue 
import time
from tkinter import *
from tkinter import ttk, filedialog, messagebox, scrolledtext 
 
class PortScannerApp:
    def __init__(self, master):
        # 主窗口设置 
        self.master  = master
        master.title(" 高级端口扫描器 v2.0")
        master.geometry("800x600") 
        master.resizable(True,  True)
        
        # 样式配置 
        self.style  = ttk.Style()
        self.style.configure('TFrame',  background='#f0f0f0')
        self.style.configure('TButton',  font=('Arial', 10))
        self.style.configure('TLabel',  background='#f0f0f0', font=('Arial', 10))
        self.style.configure('Header.TLabel',  font=('Arial', 12, 'bold'), foreground='#2c3e50')
        
        # 创建主框架 
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=BOTH,  expand=True)
        
        # 输入区域
        input_frame = ttk.LabelFrame(main_frame, text="扫描设置", padding="10")
        input_frame.pack(fill=X,  pady=(0, 10))
        
        # 目标IP输入 
        ttk.Label(input_frame, text="目标IP:").grid(row=0, column=0, padx=5, pady=5, sticky=W)
        self.ip_entry  = ttk.Entry(input_frame, width=30)
        self.ip_entry.grid(row=0,  column=1, padx=5, pady=5, sticky=W)
        self.ip_entry.insert(0,  "127.0.0.1")
        
        # 端口范围输入
        ttk.Label(input_frame, text="端口范围:").grid(row=0, column=2, padx=5, pady=5, sticky=W)
        self.port_entry  = ttk.Entry(input_frame, width=15)
        self.port_entry.grid(row=0,  column=3, padx=5, pady=5, sticky=W)
        self.port_entry.insert(0,  "80-500")
        
        # 线程数设置 
        ttk.Label(input_frame, text="线程数:").grid(row=0, column=4, padx=5, pady=5, sticky=W)
        self.thread_entry  = ttk.Entry(input_frame, width=5)
        self.thread_entry.grid(row=0,  column=5, padx=5, pady=5, sticky=W)
        self.thread_entry.insert(0,  "50")
        
        # 按钮区域
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=X,  pady=(5, 10))
        
        self.scan_btn  = ttk.Button(btn_frame, text="开始扫描", command=self.start_scan,  width=15)
        self.scan_btn.pack(side=LEFT,  padx=(0, 10))
        
        self.stop_btn  = ttk.Button(btn_frame, text="停止扫描", command=self.stop_scan,  state=DISABLED, width=15)
        self.stop_btn.pack(side=LEFT,  padx=(0, 10))
        
        self.detail_btn  = ttk.Button(btn_frame, text="扫描详情", command=self.show_details,  state=DISABLED, width=15)
        self.detail_btn.pack(side=LEFT,  padx=(0, 10))
        
        self.save_btn  = ttk.Button(btn_frame, text="保存结果", command=self.save_result,  state=DISABLED, width=15)
        self.save_btn.pack(side=LEFT) 
        
        # 结果展示区域
        result_frame = ttk.LabelFrame(main_frame, text="扫描结果", padding="5")
        result_frame.pack(fill=BOTH,  expand=True)
        
        # 创建表格 
        columns = ('port', 'service', 'status', 'response')
        self.tree  = ttk.Treeview(result_frame, columns=columns, show='headings', selectmode='browse')
        
        # 设置列标题 
        self.tree.heading('port',  text='端口')
        self.tree.heading('service',  text='服务类型')
        self.tree.heading('status',  text='状态')
        self.tree.heading('response',  text='响应时间(ms)')
        
        # 设置列宽 
        self.tree.column('port',  width=80, anchor=CENTER)
        self.tree.column('service',  width=120, anchor=CENTER)
        self.tree.column('status',  width=100, anchor=CENTER)
        self.tree.column('response',  width=120, anchor=CENTER)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(result_frame, orient=VERTICAL, command=self.tree.yview) 
        self.tree.configure(yscroll=scrollbar.set) 
        scrollbar.pack(side=RIGHT,  fill=Y)
        self.tree.pack(fill=BOTH,  expand=True)
        
        # 日志区域
        log_frame = ttk.LabelFrame(main_frame, text="操作日志", padding="5")
        log_frame.pack(fill=X,  pady=(10, 0))
        
        self.log_area  = scrolledtext.ScrolledText(log_frame, height=5, wrap=WORD)
        self.log_area.pack(fill=BOTH,  expand=True)
        self.log_area.config(state=DISABLED) 
        
        # 扫描控制变量
        self.port_queue  = queue.Queue()
        self.running  = False
        self.threads  = []
        
        # 扫描统计变量 
        self.scan_start_time  = None
        self.scan_end_time  = None
        self.total_ports  = 0 
        self.scanned_count  = 0 
        self.open_count  = 0
        self.closed_count  = 0 
        self.thread_count  = 50
        self.scan_speed  = 0 
        self.scan_duration  = 0 
        
        # 服务指纹库 
        self.service_map  = {
            20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
            80: 'HTTP', 110: 'POP3', 119: 'NNTP', 123: 'NTP',
            135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP',
            389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 2049: 'NFS',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        
        # 状态栏
        self.status_var  = StringVar()
        self.status_var.set(" 就绪")
        status_bar = ttk.Label(master, textvariable=self.status_var,  relief=SUNKEN, anchor=W)
        status_bar.pack(side=BOTTOM,  fill=X)
        
        # 添加日志
        self.add_log(" 端口扫描器已启动 - 2025年6月21日 15:03")
        self.add_log(" 请设置目标IP和端口范围，然后点击'开始扫描'")
    
    def add_log(self, message):
        """添加日志信息"""
        self.log_area.config(state=NORMAL) 
        timestamp = time.strftime("%H:%M:%S") 
        self.log_area.insert(END,  f"[{timestamp}] {message}\n")
        self.log_area.config(state=DISABLED) 
        self.log_area.see(END) 
    
    def start_scan(self):
        """开始扫描"""
        # 获取输入参数
        target_ip = self.ip_entry.get().strip() 
        port_range = self.port_entry.get().strip() 
        thread_count = self.thread_entry.get().strip() 
        
        # 验证输入
        if not target_ip:
            messagebox.showerror(" 输入错误", "请输入目标IP地址")
            return 
        
        try:
            # 解析端口范围 
            if '-' in port_range:
                start, end = map(int, port_range.split('-')) 
                port_list = list(range(start, end+1))
            elif ',' in port_range:
                port_list = [int(p) for p in port_range.split(',')] 
            else:
                port_list = [int(port_range)]
        except ValueError:
            messagebox.showerror(" 输入错误", "端口范围格式错误，请使用'起始-结束'或'端口1,端口2'格式")
            return 
        
        try:
            self.thread_count  = int(thread_count)
            if self.thread_count  < 1 or self.thread_count  > 200:
                raise ValueError 
        except ValueError:
            messagebox.showerror(" 输入错误", "线程数必须是1-200之间的整数")
            return
        
        # 初始化扫描状态 
        self.running  = True
        self.total_ports  = len(port_list)
        self.scanned_count  = 0 
        self.open_count  = 0
        self.closed_count  = 0 
        self.scan_start_time  = time.time() 
        self.scan_speed  = 0 
        
        # 清空结果 
        for item in self.tree.get_children(): 
            self.tree.delete(item) 
        
        # 初始化队列
        for port in port_list:
            self.port_queue.put(port) 
        
        # 创建扫描线程
        self.threads  = []
        for _ in range(self.thread_count): 
            t = threading.Thread(target=self.scan_worker,  args=(target_ip,))
            t.daemon  = True 
            t.start() 
            self.threads.append(t) 
        
        # 更新UI状态
        self.scan_btn.config(state=DISABLED) 
        self.stop_btn.config(state=NORMAL) 
        self.detail_btn.config(state=DISABLED) 
        self.save_btn.config(state=DISABLED) 
        self.status_var.set(f" 扫描中: {target_ip} ({self.thread_count} 线程)...")
        
        # 添加日志
        self.add_log(f" 开始扫描 {target_ip}，端口范围: {port_range}，线程数: {self.thread_count}") 
        self.add_log(f" 总计 {self.total_ports}  个端口待扫描")
        
        # 启动监控线程
        self.monitor_thread  = threading.Thread(target=self.monitor_scan) 
        self.monitor_thread.daemon  = True 
        self.monitor_thread.start() 
    
    def stop_scan(self):
        """停止扫描"""
        self.running  = False 
        self.stop_btn.config(state=DISABLED) 
        self.status_var.set(" 扫描已停止")
        self.add_log(" 扫描已手动停止")
    
    def scan_worker(self, target_ip):
        """扫描工作线程"""
        while self.running: 
            try:
                port = self.port_queue.get(timeout=0.5) 
                start_time = time.time() 
                
                try:
                    # 创建socket连接 
                    sock = socket.socket(socket.AF_INET,  socket.SOCK_STREAM)
                    sock.settimeout(1) 
                    
                    # 尝试连接
                    result = sock.connect_ex((target_ip,  port))
                    response_time = int((time.time()  - start_time) * 1000)  # 毫秒
                    
                    if result == 0:
                        status = "开放"
                        self.open_count  += 1
                        service = self.service_map.get(port,  '未知')
                        # 更新表格 
                        self.master.after(0,  self.update_table,  port, service, status, response_time)
                    else:
                        status = "关闭"
                        self.closed_count  += 1 
                    
                    # 更新扫描计数 
                    self.scanned_count  += 1
                    
                except Exception as e:
                    status = "错误"
                    self.scanned_count  += 1
                    response_time = -1
                
                finally:
                    if 'sock' in locals():
                        sock.close() 
                
                self.port_queue.task_done() 
                
            except queue.Empty:
                break 
    
    def monitor_scan(self):
        """监控扫描进度"""
        while self.running  and self.scanned_count  < self.total_ports: 
            time.sleep(0.5) 
            elapsed = time.time()  - self.scan_start_time  
            if elapsed > 0:
                self.scan_speed  = self.scanned_count  / elapsed
        
        # 扫描完成
        self.running  = False 
        self.scan_end_time  = time.time() 
        self.scan_duration  = self.scan_end_time  - self.scan_start_time 
        
        # 更新UI
        self.master.after(0,  self.on_scan_complete) 
    
    def on_scan_complete(self):
        """扫描完成处理"""
        self.scan_btn.config(state=NORMAL) 
        self.stop_btn.config(state=DISABLED) 
        self.detail_btn.config(state=NORMAL) 
        self.save_btn.config(state=NORMAL) 
        
        duration = time.strftime("%M 分%S秒", time.gmtime(self.scan_duration)) 
        self.status_var.set(f" 扫描完成! 开放端口: {self.open_count},  总耗时: {duration}")
        
        # 添加日志
        self.add_log(f" 扫描完成! 总耗时: {duration}")
        self.add_log(f" 开放端口: {self.open_count},  关闭端口: {self.closed_count}") 
        self.add_log(f" 平均扫描速度: {self.scan_speed:.1f}  端口/秒")
        
        if self.open_count  == 0:
            self.add_log(" 未检测到任何开放端口")
    
    def update_table(self, port, service, status, response_time):
        """更新结果表格"""
        status_color = '#4CAF50' if status == "开放" else '#F44336'
        
        item = self.tree.insert('',  'end', values=(port, service, status, response_time))
        
        # 为开放端口设置不同颜色
        if status == "开放":
            self.tree.tag_configure('open',  background='#E8F5E9')
            self.tree.item(item,  tags=('open',))
    
    def show_details(self):
        """显示扫描详情窗口"""
        if not self.scan_start_time: 
            return
        
        # 创建详情窗口 
        detail_win = Toplevel(self.master) 
        detail_win.title(" 扫描详情 - " + self.ip_entry.get()) 
        detail_win.geometry("500x400") 
        detail_win.resizable(True,  True)
        
        # 创建选项卡 
        notebook = ttk.Notebook(detail_win)
        notebook.pack(fill=BOTH,  expand=True, padx=10, pady=10)
        
        # 统计信息标签页
        stats_frame = ttk.Frame(notebook, padding=10)
        notebook.add(stats_frame,  text="统计信息")
        
        # 创建统计信息 
        stats = [
            ("目标地址:", self.ip_entry.get()), 
            ("扫描时间:", time.strftime("%Y-%m-%d  %H:%M:%S", time.localtime(self.scan_start_time))), 
            ("持续时间:", f"{self.scan_duration:.2f} 秒"),
            ("端口范围:", self.port_entry.get()), 
            ("总端口数:", str(self.total_ports)), 
            ("开放端口:", f"{self.open_count}  ({(self.open_count/self.total_ports*100):.1f}%)"), 
            ("关闭端口:", f"{self.closed_count}  ({(self.closed_count/self.total_ports*100):.1f}%)"), 
            ("平均速度:", f"{self.scan_speed:.1f}  端口/秒"),
            ("线程数量:", str(self.thread_count)) 
        ]
        
        # 显示统计信息 
        for i, (label, value) in enumerate(stats):
            ttk.Label(stats_frame, text=label, font=('Arial', 10, 'bold')).grid(
                row=i, column=0, padx=5, pady=2, sticky=W)
            ttk.Label(stats_frame, text=value).grid(
                row=i, column=1, padx=5, pady=2, sticky=W)
        
        # 端口详情标签页 
        port_frame = ttk.Frame(notebook, padding=10)
        notebook.add(port_frame,  text="端口详情")
        
        # 创建端口列表 
        columns = ('port', 'status', 'service')
        port_tree = ttk.Treeview(port_frame, columns=columns, show='headings', height=15)
        
        # 设置列标题
        port_tree.heading('port',  text='端口')
        port_tree.heading('status',  text='状态')
        port_tree.heading('service',  text='服务')
        
        # 设置列宽
        port_tree.column('port',  width=80, anchor=CENTER)
        port_tree.column('status',  width=80, anchor=CENTER)
        port_tree.column('service',  width=200, anchor=W)
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(port_frame, orient=VERTICAL, command=port_tree.yview) 
        port_tree.configure(yscroll=scrollbar.set) 
        scrollbar.pack(side=RIGHT,  fill=Y)
        port_tree.pack(fill=BOTH,  expand=True)
        
        # 填充端口数据 
        for item in self.tree.get_children(): 
            port, service, status, _ = self.tree.item(item)['values'] 
            port_tree.insert('',  'end', values=(port, status, service))
    
    def save_result(self):
        """保存扫描结果"""
        file_path = filedialog.asksaveasfilename( 
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                # 写入标题 
                f.write(f" 端口扫描报告 - {time.strftime('%Y-%m-%d  %H:%M:%S')}\n")
                f.write(f" 目标地址: {self.ip_entry.get()}\n") 
                f.write(f" 端口范围: {self.port_entry.get()}\n") 
                f.write(f" 扫描时间: {self.scan_duration:.2f} 秒\n")
                f.write(f" 开放端口: {self.open_count},  关闭端口: {self.closed_count}\n\n") 
                
                # 写入表头
                f.write(" 端口\t状态\t服务类型\t响应时间(ms)\n")
                f.write("-"  * 50 + "\n")
                
                # 写入扫描结果
                for item in self.tree.get_children(): 
                    port, service, status, response = self.tree.item(item)['values'] 
                    f.write(f"{port}\t{status}\t{service}\t{response}\n") 
                
                # 添加统计信息
                f.write("\n 统计信息:\n")
                f.write(f" 总端口数: {self.total_ports}\n") 
                f.write(f" 开放端口率: {(self.open_count/self.total_ports*100):.1f}%\n") 
                f.write(f" 平均扫描速度: {self.scan_speed:.1f}  端口/秒\n")
            
            self.add_log(f" 结果已保存到: {file_path}")
            messagebox.showinfo(" 保存成功", f"扫描结果已成功保存到:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror(" 保存失败", f"保存文件时出错:\n{str(e)}")
 
if __name__ == "__main__":
    root = Tk()
    app = PortScannerApp(root)
    root.mainloop() 