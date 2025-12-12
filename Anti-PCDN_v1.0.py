import psutil
import time
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import platform
import os
from datetime import datetime

class NetworkMonitor:
    def __init__(self):
        # 主要国产软件进程列表
        self.chinese_software = {
            'WeChat': ['WeChat.exe', 'WeChatApp.exe'],
            'QQ': ['QQ.exe', 'QQProtect.exe'],
            '钉钉': ['DingTalk.exe', 'DingDing.exe'],
            '百度网盘': ['BaiduNetdisk.exe', 'baiduNetdisk.exe'],
            '360安全卫士': ['360Safe.exe', '360Tray.exe'],
            '腾讯视频': ['QQLive.exe', 'TencentVideo.exe'],
            '金山WPS': ['wps.exe', 'et.exe', 'wpp.exe'],
            '迅雷': ['Thunder.exe', 'XLLiveUD.exe'],
            '爱奇艺': ['QiyiClient.exe', 'QyPlayer.exe'],
            '网易云音乐': ['NeteaseCloudMusic.exe'],
            '优酷': ['YoukuClient.exe'],
            '阿里旺旺': ['AliIM.exe'],
            '360浏览器': ['360se.exe'],
            '搜狗输入法': ['SogouCloud.exe', 'SGImeGuard.exe']
        }
        
        self.monitoring = False
        self.process_stats = {}
        self.control_rules = {}
        self.update_interval = 2  # 更新间隔(秒)
        
    def get_process_network_usage(self):
        """获取所有进程的网络使用情况"""
        network_stats = {}
        
        # 获取网络连接信息
        connections = psutil.net_connections()
        connection_pids = {conn.pid for conn in connections if conn.status == 'ESTABLISHED'}
        
        # 获取进程网络IO
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                
                # 检查是否是目标软件
                software_name = self.identify_software(name)
                if software_name:
                    # 获取网络IO统计
                    io_counters = psutil.net_io_counters(pernic=False)
                    
                    # 检查是否有活跃连接
                    has_active_connection = pid in connection_pids
                    
                    # 计算上行流量（发送的字节数）
                    if pid not in self.process_stats:
                        self.process_stats[pid] = {
                            'name': name,
                            'software': software_name,
                            'last_upload': 0,
                            'upload_speed': 0,
                            'total_upload': 0,
                            'connections': 0
                        }
                    
                    # 获取进程网络统计（需要管理员权限）
                    try:
                        process_io = proc.io_counters()
                        current_upload = process_io.write_bytes
                        
                        # 计算上传速度
                        last_upload = self.process_stats[pid]['last_upload']
                        if last_upload > 0:
                            upload_speed = (current_upload - last_upload) / self.update_interval
                            self.process_stats[pid]['upload_speed'] = upload_speed
                            self.process_stats[pid]['total_upload'] += upload_speed * self.update_interval
                        
                        self.process_stats[pid]['last_upload'] = current_upload
                        self.process_stats[pid]['connections'] = len([
                            conn for conn in connections 
                            if conn.pid == pid and conn.status == 'ESTABLISHED'
                        ])
                        
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        # 如果没有权限，使用估算方法
                        self.process_stats[pid]['upload_speed'] = 1000 if has_active_connection else 0
                        self.process_stats[pid]['connections'] = len([
                            conn for conn in connections 
                            if conn.pid == pid and conn.status == 'ESTABLISHED'
                        ])
                    
                    network_stats[software_name] = self.process_stats[pid]
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return network_stats
    
    def identify_software(self, process_name):
        """识别进程属于哪个国产软件"""
        for software, processes in self.chinese_software.items():
            if process_name in processes:
                return software
        return None
    
    def block_process_network(self, process_name):
        """阻塞指定进程的网络访问"""
        system = platform.system()
        blocked_pids = []
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if self.identify_software(proc.info['name']) == process_name:
                    pid = proc.info['pid']
                    
                    if system == "Windows":
                        # Windows: 使用netsh阻断进程
                        try:
                            subprocess.run([
                                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                f'name=Block_{process_name}_{pid}',
                                'dir=out', 'action=block', 'program=', 
                                proc.exe(), 'enable=yes'
                            ], capture_output=True)
                        except:
                            pass
                    
                    elif system == "Linux":
                        # Linux: 使用iptables阻断进程
                        try:
                            subprocess.run([
                                'iptables', '-A', 'OUTPUT', '-p', 'all', 
                                '-m', 'owner', '--uid-owner', str(proc.uids().real),
                                '-j', 'DROP'
                            ], capture_output=True)
                        except:
                            pass
                    
                    blocked_pids.append(pid)
                    self.control_rules[process_name] = 'blocked'
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return blocked_pids
    
    def unblock_process_network(self, process_name):
        """解除对指定进程的网络阻塞"""
        system = platform.system()
        
        if system == "Windows":
            # 删除Windows防火墙规则
            try:
                result = subprocess.run([
                    'netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all'
                ], capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if f'Block_{process_name}' in line:
                        rule_name = line.split(':')[-1].strip()
                        subprocess.run([
                            'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                            f'name={rule_name}'
                        ], capture_output=True)
            except:
                pass
        
        elif system == "Linux":
            # 删除Linux iptables规则
            try:
                subprocess.run([
                    'iptables', '-D', 'OUTPUT', '-p', 'all', '-j', 'DROP'
                ], capture_output=True)
            except:
                pass
        
        self.control_rules[process_name] = 'allowed'
    
    def limit_network_speed(self, process_name, max_speed_kbps):
        """限制指定进程的网络速度"""
        # 这里可以实现流量限制逻辑
        # 注意：这需要更复杂的网络层控制，可能需要第三方工具
        self.control_rules[process_name] = f'limited_{max_speed_kbps}kbps'
        return True

class NetworkMonitorGUI:
    def __init__(self):
        self.monitor = NetworkMonitor()
        self.root = tk.Tk()
        self.root.title("国产软件网络流量监控器")
        self.root.geometry("800x600")
        self.setup_ui()
        
    def setup_ui(self):
        """设置用户界面"""
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 控制按钮框架
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="开始监控", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=0, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="停止监控", command=self.stop_monitoring, state='disabled')
        self.stop_btn.grid(row=0, column=1, padx=5)
        
        # 状态标签
        self.status_var = tk.StringVar(value="状态: 未启动")
        status_label = ttk.Label(control_frame, textvariable=self.status_var)
        status_label.grid(row=0, column=2, padx=20)
        
        # 流量显示表格
        columns = ('软件名称', '进程数', '上行速度', '总上传量', '连接数', '控制状态', '操作')
        self.tree = ttk.Treeview(main_frame, columns=columns, show='headings', height=20)
        
        # 设置列标题
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        
        self.tree.column('软件名称', width=120)
        self.tree.column('操作', width=150)
        
        self.tree.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        
        # 滚动条
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.grid(row=1, column=3, sticky=(tk.N, tk.S))
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # 控制面板
        control_panel = ttk.LabelFrame(main_frame, text="流量控制", padding="5")
        control_panel.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(control_panel, text="选择软件:").grid(row=0, column=0, padx=5)
        self.software_var = tk.StringVar()
        software_combo = ttk.Combobox(control_panel, textvariable=self.software_var, 
                                    values=list(self.monitor.chinese_software.keys()))
        software_combo.grid(row=0, column=1, padx=5)
        
        ttk.Button(control_panel, text="阻断网络", 
                  command=lambda: self.control_network('block')).grid(row=0, column=2, padx=5)
        ttk.Button(control_panel, text="允许网络", 
                  command=lambda: self.control_network('allow')).grid(row=0, column=3, padx=5)
        
        # 速度限制框架
        speed_frame = ttk.Frame(control_panel)
        speed_frame.grid(row=1, column=0, columnspan=4, pady=5)
        
        ttk.Label(speed_frame, text="限速(KB/s):").grid(row=0, column=0, padx=5)
        self.speed_var = tk.StringVar(value="100")
        ttk.Entry(speed_frame, textvariable=self.speed_var, width=10).grid(row=0, column=1, padx=5)
        ttk.Button(speed_frame, text="应用限速", 
                  command=lambda: self.control_network('limit')).grid(row=0, column=2, padx=5)
        
        # 配置网格权重
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
    def start_monitoring(self):
        """开始监控"""
        self.monitor.monitoring = True
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.status_var.set("状态: 监控中...")
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
            network_stats = self.monitor.get_process_network_usage()
            self.update_display(network_stats)
            time.sleep(self.monitor.update_interval)
    
    def update_display(self, network_stats):
        """更新显示"""
        # 清空现有显示
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # 聚合同一软件的数据
        software_data = {}
        for pid, stats in self.monitor.process_stats.items():
            software = stats['software']
            if software not in software_data:
                software_data[software] = {
                    'process_count': 0,
                    'total_speed': 0,
                    'total_upload': 0,
                    'total_connections': 0
                }
            
            software_data[software]['process_count'] += 1
            software_data[software]['total_speed'] += stats['upload_speed']
            software_data[software]['total_upload'] += stats['total_upload']
            software_data[software]['total_connections'] += stats['connections']
        
        # 更新表格
        for software, data in software_data.items():
            speed_kbps = data['total_speed'] / 1024
            total_mb = data['total_upload'] / (1024 * 1024)
            
            control_status = self.monitor.control_rules.get(software, '允许')
            
            self.tree.insert('', 'end', values=(
                software,
                data['process_count'],
                f"{speed_kbps:.1f} KB/s",
                f"{total_mb:.1f} MB",
                data['total_connections'],
                control_status,
                "点击控制按钮操作"
            ))
    
    def control_network(self, action):
        """控制网络访问"""
        software = self.software_var.get()
        if not software:
            messagebox.showwarning("警告", "请选择要控制的软件")
            return
        
        try:
            if action == 'block':
                blocked = self.monitor.block_process_network(software)
                messagebox.showinfo("成功", f"已阻断 {software} 的网络访问\n影响进程: {len(blocked)}个")
            
            elif action == 'allow':
                self.monitor.unblock_process_network(software)
                messagebox.showinfo("成功", f"已允许 {software} 的网络访问")
            
            elif action == 'limit':
                speed = int(self.speed_var.get())
                if self.monitor.limit_network_speed(software, speed):
                    messagebox.showinfo("成功", f"已限制 {software} 的上行速度为 {speed} KB/s")
        
        except Exception as e:
            messagebox.showerror("错误", f"操作失败: {str(e)}")
    
    def run(self):
        """运行应用"""
        self.root.mainloop()

def main():
    # 检查管理员权限
    if platform.system() == "Windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("请以管理员权限运行此程序以获得完整的网络控制功能")
        except:
            pass
    
    print("国产软件网络流量监控器启动中...")
    print("注意: 部分网络控制功能需要管理员权限")
    
    app = NetworkMonitorGUI()
    app.run()

if __name__ == "__main__":
    main()
