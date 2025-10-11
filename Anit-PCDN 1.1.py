import psutil
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import os
from datetime import datetime
import json

class PIDNetworkMonitor:
    def __init__(self):
        # 定义要监控的软件及其常见进程名
        self.target_processes = {
            'WeChat': ['WeChat.exe', 'WeChatApp.exe'],
            'QQ': ['QQ.exe', 'QQProtect.exe'],
            '百度网盘': ['BaiduNetdisk.exe', 'baiduNetdisk.exe'],
            '腾讯视频': ['QQLive.exe', 'TencentVideo.exe', 'QyClient.exe'],
            '迅雷': ['Thunder.exe', 'XLLiveUD.exe'],
            '爱奇艺': ['QiyiClient.exe', 'QyPlayer.exe'],
            '网易云音乐': ['NeteaseCloudMusic.exe'],
            '优酷': ['YoukuClient.exe'],
            '搜狗输入法': ['SogouCloud.exe', 'SGImeGuard.exe']
        }
        
        self.monitoring = True
        self.process_stats = {}  # 存储PID和对应的统计信息
        self.blocked_pids = set()  # 被阻断的PID集合
        self.update_interval = 2
        
        # 加载保存的阻断规则
        self.load_blocked_pids()
    
    def load_blocked_pids(self):
        """加载保存的阻断PID列表"""
        try:
            if os.path.exists("blocked_pids.json"):
                with open("blocked_pids.json", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.blocked_pids = set(data.get("blocked_pids", []))
                    print(f"已加载 {len(self.blocked_pids)} 个被阻断的PID")
        except Exception as e:
            print(f"加载阻断PID列表失败: {e}")
    
    def save_blocked_pids(self):
        """保存阻断PID列表"""
        try:
            with open("blocked_pids.json", "w", encoding="utf-8") as f:
                json.dump({"blocked_pids": list(self.blocked_pids)}, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"保存阻断PID列表失败: {e}")
    
    def scan_processes(self):
        """扫描所有进程，识别目标软件"""
        current_pids = {}
        
        for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'create_time']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # 检查是否是目标软件
                software_name = self.identify_software(name)
                if software_name:
                    current_pids[pid] = {
                        'name': name,
                        'software': software_name,
                        'create_time': proc.info['create_time'],
                        'connections': 0,
                        'upload_speed': 0,
                        'total_upload': 0,
                        'last_bytes_sent': 0,
                        'last_update': time.time()
                    }
                    
                    # 如果是新进程，初始化统计信息
                    if pid not in self.process_stats:
                        self.process_stats[pid] = current_pids[pid].copy()
                        # 获取初始网络统计
                        net_io = psutil.net_io_counters(pernic=False)
                        if net_io:
                            self.process_stats[pid]['last_bytes_sent'] = net_io.bytes_sent
                    
                    # 应用网络控制
                    if pid in self.blocked_pids:
                        self.block_pid_network(pid)
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        # 清理已退出的进程
        dead_pids = set(self.process_stats.keys()) - set(current_pids.keys())
        for pid in dead_pids:
            if pid in self.process_stats:
                del self.process_stats[pid]
            if pid in self.blocked_pids:
                self.blocked_pids.remove(pid)
        
        return current_pids
    
    def identify_software(self, process_name):
        """识别进程属于哪个软件"""
        for software, processes in self.target_processes.items():
            if process_name in processes:
                return software
        return None
    
    def update_network_stats(self):
        """更新网络统计信息"""
        # 获取当前网络IO
        net_io = psutil.net_io_counters(pernic=False)
        current_bytes_sent = net_io.bytes_sent if net_io else 0
        
        # 获取所有网络连接
        connections = psutil.net_connections()
        process_connections = {}
        
        for conn in connections:
            if conn.pid and conn.status == 'ESTABLISHED':
                if conn.pid not in process_connections:
                    process_connections[conn.pid] = 0
                process_connections[conn.pid] += 1
        
        # 更新每个进程的统计信息
        for pid, stats in self.process_stats.items():
            try:
                # 更新连接数
                stats['connections'] = process_connections.get(pid, 0)
                
                # 计算上传速度
                time_diff = time.time() - stats['last_update']
                if time_diff > 0:
                    bytes_diff = current_bytes_sent - stats['last_bytes_sent']
                    stats['upload_speed'] = bytes_diff / time_diff  # 字节/秒
                    
                    # 更新总上传量（限制在合理范围内）
                    if 0 <= stats['upload_speed'] <= 100 * 1024 * 1024:
                        stats['total_upload'] += stats['upload_speed'] * time_diff
                
                stats['last_bytes_sent'] = current_bytes_sent
                stats['last_update'] = time.time()
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def get_process_stats(self):
        """获取所有目标进程的统计信息"""
        self.scan_processes()
        self.update_network_stats()
        return self.aggregate_stats()
    
    def aggregate_stats(self):
        """按软件聚合统计信息"""
        software_stats = {}
        
        for pid, stats in self.process_stats.items():
            software = stats['software']
            if software not in software_stats:
                software_stats[software] = {
                    'process_count': 0,
                    'total_speed': 0,
                    'total_upload': 0,
                    'total_connections': 0,
                    'pids': []
                }
            
            software_stats[software]['process_count'] += 1
            software_stats[software]['total_speed'] += stats['upload_speed']
            software_stats[software]['total_upload'] += stats['total_upload']
            software_stats[software]['total_connections'] += stats['connections']
            software_stats[software]['pids'].append(pid)
        
        return software_stats
    
    def block_pid_network(self, pid):
        """阻断指定PID的网络访问"""
        if pid in self.blocked_pids:
            return True
            
        system = platform.system()
        try:
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            
            if system == "Windows":
                # 使用Windows防火墙阻断
                try:
                    result = subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                        f'name=Block_PID_{pid}',
                        'dir=out', 'action=block', 'program=', exe_path, 'enable=yes'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        self.blocked_pids.add(pid)
                        self.save_blocked_pids()
                        print(f"成功阻断PID {pid} 的网络访问")
                        return True
                    else:
                        print(f"阻断PID {pid} 失败: {result.stderr}")
                except subprocess.TimeoutExpired:
                    print(f"阻断PID {pid} 超时")
                except Exception as e:
                    print(f"阻断PID {pid} 失败: {e}")
            
            elif system == "Linux":
                # 使用iptables阻断
                try:
                    subprocess.run([
                        'iptables', '-A', 'OUTPUT', '-p', 'all', 
                        '-m', 'owner', '--pid-owner', str(pid),
                        '-j', 'DROP'
                    ], capture_output=True, timeout=10)
                    self.blocked_pids.add(pid)
                    self.save_blocked_pids()
                    return True
                except subprocess.TimeoutExpired:
                    print(f"阻断PID {pid} 超时")
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"无法访问PID {pid}: {e}")
        
        return False
    
    def unblock_pid_network(self, pid):
        """解除对指定PID的网络阻断"""
        if pid not in self.blocked_pids:
            return True
            
        system = platform.system()
        
        try:
            if system == "Windows":
                # 删除Windows防火墙规则
                try:
                    result = subprocess.run([
                        'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                        f'name=Block_PID_{pid}'
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        self.blocked_pids.discard(pid)
                        self.save_blocked_pids()
                        print(f"成功解除PID {pid} 的网络阻断")
                        return True
                    else:
                        print(f"解除PID {pid} 阻断失败: {result.stderr}")
                except subprocess.TimeoutExpired:
                    print(f"解除PID {pid} 阻断超时")
            
            elif system == "Linux":
                # 删除iptables规则
                try:
                    subprocess.run([
                        'iptables', '-D', 'OUTPUT', '-p', 'all', 
                        '-m', 'owner', '--pid-owner', str(pid),
                        '-j', 'DROP'
                    ], capture_output=True, timeout=10)
                    self.blocked_pids.discard(pid)
                    self.save_blocked_pids()
                    return True
                except subprocess.TimeoutExpired:
                    print(f"解除PID {pid} 阻断超时")
        
        except Exception as e:
            print(f"解除PID {pid} 阻断失败: {e}")
        
        return False
    
    def block_software_network(self, software_name):
        """阻断指定软件的所有进程网络"""
        print(f"尝试阻断软件: {software_name}")
        
        # 找到该软件的所有PID
        target_pids = []
        for pid, stats in self.process_stats.items():
            if stats['software'] == software_name:
                target_pids.append(pid)
        
        # 阻断所有相关PID
        blocked_count = 0
        for pid in target_pids:
            if self.block_pid_network(pid):
                blocked_count += 1
        
        print(f"成功阻断 {software_name} 的 {blocked_count} 个进程")
        return blocked_count > 0
    
    def unblock_software_network(self, software_name):
        """解除对指定软件的所有进程的网络阻断"""
        print(f"尝试解除阻断软件: {software_name}")
        
        # 解除阻断所有相关PID
        unblocked_count = 0
        for pid in list(self.blocked_pids):
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                if self.identify_software(proc_name) == software_name:
                    if self.unblock_pid_network(pid):
                        unblocked_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.blocked_pids.discard(pid)
        
        print(f"成功解除阻断 {software_name} 的 {unblocked_count} 个进程")
        return unblocked_count > 0
    
    def block_specific_pid(self, pid):
        """阻断指定PID的网络访问"""
        return self.block_pid_network(pid)
    
    def unblock_specific_pid(self, pid):
        """解除对指定PID的网络阻断"""
        return self.unblock_pid_network(pid)
    
    def cleanup_all_rules(self):
        """清理所有防火墙规则"""
        system = platform.system()
        
        if system == "Windows":
            try:
                # 获取所有规则
                result = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
                ], capture_output=True, text=True, timeout=10)
                
                # 查找并删除相关规则
                for line in result.stdout.split('\n'):
                    if 'Block_PID_' in line:
                        rule_name = line.split(':')[-1].strip()
                        try:
                            subprocess.run([
                                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                                f'name={rule_name}'
                            ], capture_output=True, timeout=5)
                        except:
                            pass
            except:
                pass
        
        # 清空阻断PID列表
        self.blocked_pids.clear()
        self.save_blocked_pids()
        
        print("已清理所有网络控制规则")

class PIDNetworkMonitorGUI:
    def __init__(self):
        self.monitor = PIDNetworkMonitor()
        self.root = tk.Tk()
        self.root.title("PID网络流量监控器 v3.0")
        self.root.geometry("1000x700")
        
        # 设置窗口图标
        try:
            self.root.iconbitmap("network.ico")
        except:
            pass
        
        self.setup_ui()
        self.start_monitoring()
        
    def setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 控制按钮框架
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=0, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="开始监控", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="停止监控", command=self.stop_monitoring)
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        # 状态标签
        self.status_var = tk.StringVar(value="状态: 监控中...")
        status_label = ttk.Label(control_frame, textvariable=self.status_var, foreground="green")
        status_label.grid(row=0, column=2, padx=20)
        
        # 流量显示表格
        columns = ('软件名称', 'PID', '进程名', '上行速度', '总上传量', '连接数', '控制状态')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)
        
        # 设置列标题
        for col in columns:
            self.tree.heading(col, text=col)
        
        # 设置列宽
        self.tree.column('软件名称', width=120)
        self.tree.column('PID', width=80)
        self.tree.column('进程名', width=120)
        self.tree.column('上行速度', width=100)
        self.tree.column('总上传量', width=100)
        self.tree.column('连接数', width=80)
        self.tree.column('控制状态', width=100)
        
        self.tree.grid(row=1, column=0, columnspan=4, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=1, column=4, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 控制面板
        control_panel = ttk.LabelFrame(main_frame, text="流量控制", padding="5")
        control_panel.grid(row=2, column=0, columnspan=4, sticky=(tk.W, tk.E), pady=5)
        
        # 软件级别控制
        ttk.Label(control_panel, text="选择软件:").grid(row=0, column=0, padx=5)
        self.software_var = tk.StringVar()
        software_combo = ttk.Combobox(control_panel, textvariable=self.software_var, 
                                    values=list(self.monitor.target_processes.keys()))
        software_combo.grid(row=0, column=1, padx=5)
        
        ttk.Button(control_panel, text="阻断软件网络", 
                  command=lambda: self.control_software_network('block')).grid(row=0, column=2, padx=5)
        ttk.Button(control_panel, text="允许软件网络", 
                  command=lambda: self.control_software_network('allow')).grid(row=0, column=3, padx=5)
        
        # PID级别控制
        ttk.Label(control_panel, text="PID:").grid(row=1, column=0, padx=5, pady=5)
        self.pid_var = tk.StringVar()
        ttk.Entry(control_panel, textvariable=self.pid_var, width=10).grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Button(control_panel, text="阻断PID网络", 
                  command=lambda: self.control_pid_network('block')).grid(row=1, column=2, padx=5, pady=5)
        ttk.Button(control_panel, text="允许PID网络", 
                  command=lambda: self.control_pid_network('allow')).grid(row=1, column=3, padx=5, pady=5)
        
        ttk.Button(control_panel, text="清理所有规则", 
                  command=self.cleanup_all_rules).grid(row=1, column=4, padx=5, pady=5)
        
        # 绑定树形视图选择事件
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # 绑定关闭事件
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def on_tree_select(self, event):
        """当选择树形视图中的项目时，自动填充PID"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            values = item['values']
            if len(values) > 1:
                self.pid_var.set(str(values[1]))  # PID在第二列
    
    def start_monitoring(self):
        """开始监控"""
        self.monitor.monitoring = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("状态: 监控中...")
        
        # 在单独的线程中运行监控
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """停止监控"""
        self.monitor.monitoring = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.status_var.set("状态: 已停止")
    
    def _monitoring_loop(self):
        """监控循环"""
        while self.monitor.monitoring:
            try:
                process_stats = self.monitor.get_process_stats()
                self.root.after(0, self.update_display, process_stats)
                time.sleep(self.monitor.update_interval)
            except Exception as e:
                print(f"监控循环错误: {e}")
                time.sleep(self.monitor.update_interval)
    
    def update_display(self, process_stats):
        """更新显示"""
        # 清空现有显示
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 更新表格 - 显示每个PID的详细信息
        for software, data in process_stats.items():
            for pid in data['pids']:
                if pid in self.monitor.process_stats:
                    stats = self.monitor.process_stats[pid]
                    speed_kbps = stats['upload_speed'] / 1024 if stats['upload_speed'] > 0 else 0
                    total_mb = stats['total_upload'] / (1024 * 1024)
                    
                    # 检查控制状态
                    control_status = "已阻断" if pid in self.monitor.blocked_pids else "允许"
                    
                    # 添加上行速度显示颜色
                    speed_text = f"{speed_kbps:.1f} KB/s"
                    if speed_kbps > 100:  # 高速流量显示为红色
                        speed_text = f"{speed_kbps:.1f} KB/s 🔴"
                    elif speed_kbps > 10:  # 中速流量显示为黄色
                        speed_text = f"{speed_kbps:.1f} KB/s 🟡"
                    
                    self.tree.insert('', 'end', values=(
                        software,
                        pid,
                        stats['name'],
                        speed_text,
                        f"{total_mb:.2f} MB",
                        stats['connections'],
                        control_status
                    ))
    
    def control_software_network(self, action):
        """控制软件网络访问"""
        software = self.software_var.get()
        if not software:
            messagebox.showwarning("警告", "请选择要控制的软件")
            return
        
        try:
            if action == 'block':
                if self.monitor.block_software_network(software):
                    messagebox.showinfo("成功", f"已阻断 {software} 的网络访问")
                else:
                    messagebox.showwarning("警告", f"未能阻断 {software}，可能没有找到活跃进程")
            
            elif action == 'allow':
                if self.monitor.unblock_software_network(software):
                    messagebox.showinfo("成功", f"已允许 {software} 的网络访问")
                else:
                    messagebox.showinfo("信息", f"{software} 的网络访问已恢复")
        
        except Exception as e:
            messagebox.showerror("错误", f"操作失败: {str(e)}")
    
    def control_pid_network(self, action):
        """控制PID网络访问"""
        pid_str = self.pid_var.get()
        if not pid_str:
            messagebox.showwarning("警告", "请输入PID")
            return
        
        try:
            pid = int(pid_str)
            
            if action == 'block':
                if self.monitor.block_specific_pid(pid):
                    messagebox.showinfo("成功", f"已阻断 PID {pid} 的网络访问")
                else:
                    messagebox.showwarning("警告", f"未能阻断 PID {pid}")
            
            elif action == 'allow':
                if self.monitor.unblock_specific_pid(pid):
                    messagebox.showinfo("成功", f"已允许 PID {pid} 的网络访问")
                else:
                    messagebox.showinfo("信息", f"PID {pid} 的网络访问已恢复")
        
        except ValueError:
            messagebox.showerror("错误", "PID必须是数字")
        except Exception as e:
            messagebox.showerror("错误", f"操作失败: {str(e)}")
    
    def cleanup_all_rules(self):
        """清理所有防火墙规则"""
        try:
            self.monitor.cleanup_all_rules()
            messagebox.showinfo("成功", "已清理所有网络控制规则")
        except Exception as e:
            messagebox.showerror("错误", f"清理规则失败: {str(e)}")
    
    def on_closing(self):
        """程序关闭时的处理"""
        self.monitor.monitoring = False
        self.root.destroy()
    
    def run(self):
        """运行应用程序"""
        self.root.mainloop()

def main():
    # 检查管理员权限
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("请以管理员权限运行此程序以获得完整的网络控制功能")
                response = messagebox.askyesno(
                    "权限提示", 
                    "网络阻断功能需要管理员权限。\n是否继续运行？"
                )
                if not response:
                    return
        except:
            pass
    
    print("程序启动中...")
    print("注意: 网络阻断功能需要管理员权限")
    
    app = PIDNetworkMonitorGUI()
    app.run()

if __name__ == "__main__":
    main()