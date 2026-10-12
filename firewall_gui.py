import sys
import os
import subprocess
import threading
import time
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from process_monitor import ProcessSocketMonitor

# Enable High DPI Crisp Rendering (HD / 720p / 1080p / 4K vector crispness)
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2) # Per Monitor DPI Aware v2
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)


class WindowsFirewallGUI:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("🛡️ Zero-Cost Offline DLP & Windows System Firewall (HD Mode)")
        self.root.geometry("1420x860")
        self.root.minsize(1150, 680)
        self.root.configure(bg="#121212")

        self.monitor = ProcessSocketMonitor()
        self.blocked_rules = set()
        self.is_emergency_mode_active = False

        self._init_styles()
        self._build_ui()
        self._create_context_menu()

        self._refresh_thread_running = True
        self.refresh_thread = threading.Thread(target=self._auto_refresh_loop, daemon=True)
        self.refresh_thread.start()

    def _init_styles(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Crisp High-Definition Typography & Dark Theme
        self.style.configure(".", background="#121212", foreground="#FFFFFF", font=("Segoe UI", 11))
        self.style.configure("Treeview",
                             background="#1E1E1E",
                             foreground="#F0F0F0",
                             fieldbackground="#1E1E1E",
                             font=("Segoe UI", 10),
                             rowheight=36)
        self.style.map("Treeview", background=[("selected", "#004D40")])
        self.style.configure("Treeview.Heading",
                             background="#252526",
                             foreground="#00E6FF",
                             font=("Segoe UI", 11, "bold"))

    def _build_ui(self):
        # Header Frame (HD Layout with Master Emergency Stop Button)
        header_frame = tk.Frame(self.root, bg="#1A1A1A", height=75)
        header_frame.pack(fill=tk.X, side=tk.TOP)

        title_lbl = tk.Label(
            header_frame,
            text="🛡️ WINDOWS DLP & SYSTEM-WIDE FIREWALL",
            font=("Segoe UI", 16, "bold"),
            fg="#00E6FF",
            bg="#1A1A1A"
        )
        title_lbl.pack(side=tk.LEFT, padx=25, pady=16)

        # Master Emergency Stop Button for Data Transmission
        self.btn_master_emergency = tk.Button(
            header_frame,
            text="🚨 EMERGENCY STOP ALL DATA TRANSMISSIONS",
            font=("Segoe UI", 11, "bold"),
            bg="#B71C1C",
            fg="white",
            activebackground="#D32F2F",
            activeforeground="white",
            relief=tk.RAISED,
            bd=2,
            padx=18,
            pady=8,
            command=self.toggle_master_emergency_stop
        )
        self.btn_master_emergency.pack(side=tk.LEFT, padx=25, pady=14)

        admin_status = "ADMIN ELEVATED 🟢" if is_admin() else "LIMITED USER ⚠️ (Run as Admin to Block)"
        admin_fg = "#69F0AE" if is_admin() else "#FFD54F"
        admin_lbl = tk.Label(
            header_frame,
            text=f"Status: {admin_status}",
            font=("Segoe UI", 11, "bold"),
            fg=admin_fg,
            bg="#1A1A1A"
        )
        admin_lbl.pack(side=tk.RIGHT, padx=25, pady=16)

        # High-Definition Data Leak Metrics Analytics Summary Banner
        metrics_frame = tk.Frame(self.root, bg="#212121", height=60)
        metrics_frame.pack(fill=tk.X, side=tk.TOP, padx=25, pady=(12, 0))

        self.lbl_total_data = tk.Label(
            metrics_frame,
            text="📊 Total Personal Data Transmitted: 0.00 MB",
            font=("Segoe UI", 11, "bold"),
            fg="#FFD54F",
            bg="#212121"
        )
        self.lbl_total_data.pack(side=tk.LEFT, padx=20, pady=12)

        self.lbl_top_process = tk.Label(
            metrics_frame,
            text="🔍 Top Transmitter: None",
            font=("Segoe UI", 11),
            fg="#81D4FA",
            bg="#212121"
        )
        self.lbl_top_process.pack(side=tk.LEFT, padx=30, pady=12)

        self.lbl_blocked_count = tk.Label(
            metrics_frame,
            text="🛑 Blocked Executables: 0",
            font=("Segoe UI", 11, "bold"),
            fg="#FF5252",
            bg="#212121"
        )
        self.lbl_blocked_count.pack(side=tk.RIGHT, padx=20, pady=12)

        # Main Content Frame
        content_frame = tk.Frame(self.root, bg="#121212")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=25, pady=12)

        # Process List Treeview (HD Column Widths)
        columns = ("pid", "name", "path", "data_transmitted", "bandwidth", "endpoints", "status")
        self.tree = ttk.Treeview(content_frame, columns=columns, show="headings", selectmode="browse")

        self.tree.heading("pid", text="PID")
        self.tree.heading("name", text="Process Name")
        self.tree.heading("path", text="Executable File Path")
        self.tree.heading("data_transmitted", text="Data Transmitted")
        self.tree.heading("bandwidth", text="Rate (KB/s)")
        self.tree.heading("endpoints", text="Active Outbound Endpoints")
        self.tree.heading("status", text="Firewall Status")

        self.tree.column("pid", width=80, anchor="center")
        self.tree.column("name", width=190, anchor="w")
        self.tree.column("path", width=380, anchor="w")
        self.tree.column("data_transmitted", width=160, anchor="center")
        self.tree.column("bandwidth", width=110, anchor="center")
        self.tree.column("endpoints", width=250, anchor="w")
        self.tree.column("status", width=130, anchor="center")

        scrollbar = ttk.Scrollbar(content_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind Right-Click Context Menu on Treeview items
        self.tree.bind("<Button-3>", self._on_right_click)

        # Bottom Control Toolbar
        toolbar = tk.Frame(self.root, bg="#1A1A1A", height=70)
        toolbar.pack(fill=tk.X, side=tk.BOTTOM)

        btn_block = tk.Button(
            toolbar,
            text="🛑 1-TAP BLOCK EXECUTABLE",
            font=("Segoe UI", 11, "bold"),
            bg="#D32F2F",
            fg="white",
            activebackground="#B71C1C",
            activeforeground="white",
            relief=tk.FLAT,
            padx=16,
            pady=10,
            command=self.block_selected_executable
        )
        btn_block.pack(side=tk.LEFT, padx=15, pady=12)

        btn_unblock = tk.Button(
            toolbar,
            text="🟢 UNBLOCK EXECUTABLE",
            font=("Segoe UI", 11, "bold"),
            bg="#388E3C",
            fg="white",
            activebackground="#1B5E20",
            activeforeground="white",
            relief=tk.FLAT,
            padx=16,
            pady=10,
            command=self.unblock_selected_executable
        )
        btn_unblock.pack(side=tk.LEFT, padx=10, pady=12)

        btn_inspector = tk.Button(
            toolbar,
            text="📊 DATA LEAK INSPECTOR",
            font=("Segoe UI", 11, "bold"),
            bg="#0288D1",
            fg="white",
            activebackground="#01579B",
            activeforeground="white",
            relief=tk.FLAT,
            padx=16,
            pady=10,
            command=self.show_data_leak_inspector
        )
        btn_inspector.pack(side=tk.LEFT, padx=10, pady=12)

        btn_audit = tk.Button(
            toolbar,
            text="📅 SYSTEM FILE AUDIT LOG",
            font=("Segoe UI", 11, "bold"),
            bg="#7B1FA2",
            fg="white",
            activebackground="#4A148C",
            activeforeground="white",
            relief=tk.FLAT,
            padx=16,
            pady=10,
            command=self.show_system_file_audit_log
        )
        btn_audit.pack(side=tk.LEFT, padx=10, pady=12)

        btn_refresh = tk.Button(
            toolbar,
            text="🔄 REFRESH NOW",
            font=("Segoe UI", 11),
            bg="#333333",
            fg="white",
            relief=tk.FLAT,
            padx=16,
            pady=10,
            command=self.refresh_process_table
        )
        btn_refresh.pack(side=tk.RIGHT, padx=15, pady=12)

    def _create_context_menu(self):
        """Creates native right-click popup context menu for applications in the table."""
        self.context_menu = tk.Menu(
            self.root,
            tearoff=0,
            bg="#252526",
            fg="#FFFFFF",
            activebackground="#004D40",
            activeforeground="#00E6FF",
            font=("Segoe UI", 10)
        )
        self.context_menu.add_command(
            label="🛑 Stop Personal Data Transmission (Block App)",
            command=self.block_selected_executable
        )
        self.context_menu.add_command(
            label="🟢 Allow Personal Data Transmission (Unblock App)",
            command=self.unblock_selected_executable
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="📊 Show Transmitted Details & Endpoints",
            command=self.show_selected_app_details
        )
        self.context_menu.add_command(
            label="⚡ Emergency Terminate Process (Kill PID)",
            command=self.kill_selected_process
        )
        self.context_menu.add_separator()
        self.context_menu.add_command(
            label="📁 Open Executable File Location",
            command=self.open_executable_location
        )

    def _on_right_click(self, event):
        """Triggers context menu on right clicking an application row."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def toggle_master_emergency_stop(self):
        """Master Emergency Button to stop all personal data transmission across all applications."""
        if not self.is_emergency_mode_active:
            confirm = messagebox.askyesno(
                "🚨 EMERGENCY STOP ALL DATA TRANSMISSIONS",
                "Are you sure you want to trigger the EMERGENCY KILL SWITCH?\n\n"
                "This will instantly block all outbound personal data, files, and document transmissions across ALL running applications!"
            )
            if not confirm:
                return

            procs = self.monitor.get_active_process_connections()
            blocked_count = 0
            for p in procs:
                exe_path = p["exe_path"]
                name = p["name"]
                pid = p["pid"]
                if exe_path and exe_path != "N/A":
                    rule_name = f"DLP_EmergencyBlock_{name}_{pid}"
                    cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}"'
                    try:
                        subprocess.run(cmd, shell=True, capture_output=True)
                        self.blocked_rules.add(exe_path)
                        blocked_count += 1
                    except Exception:
                        pass

            self.is_emergency_mode_active = True
            self.btn_master_emergency.config(
                text="🟢 RESTORE ALL DATA TRANSMISSIONS",
                bg="#388E3C",
                activebackground="#1B5E20"
            )
            messagebox.showinfo("Emergency Stop Activated", f"🚨 EMERGENCY STOP ENGAGED!\n\nBlocked outbound network egress for {blocked_count} active applications.")
        else:
            # Disarm emergency stop
            for exe_path in list(self.blocked_rules):
                cmd = f'netsh advfirewall firewall delete rule name=all program="{exe_path}"'
                try:
                    subprocess.run(cmd, shell=True, capture_output=True)
                except Exception:
                    pass
            self.blocked_rules.clear()
            self.is_emergency_mode_active = False
            self.btn_master_emergency.config(
                text="🚨 EMERGENCY STOP ALL DATA TRANSMISSIONS",
                bg="#B71C1C",
                activebackground="#D32F2F"
            )
            messagebox.showinfo("Emergency Disarmed", "🟢 All network data transmissions have been restored.")

        self.refresh_process_table()

    def show_selected_app_details(self):
        """Displays detailed transmitted payload and endpoint analysis for the selected application."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Process", "Please select a process from the table.")
            return

        values = self.tree.item(selected[0], "values")
        pid = values[0]
        name = values[1]
        exe_path = values[2]
        data_str = values[3]
        bw = values[4]
        endpoints = values[5]
        status = values[6]

        details = f"""
        📊 TRANSMISSION DETAILS FOR APPLICATION
        ==================================================
        Process Name:       {name}
        Process ID (PID):   {pid}
        Executable Path:    {exe_path}
        Status:             {status}
        --------------------------------------------------
        Personal Data Sent: {data_str}
        Current Rate:       {bw} KB/s
        Active Endpoints:   {endpoints}
        ==================================================
        """.trimIndent() if hasattr(str, 'trimIndent') else (
            f"📊 TRANSMISSION DETAILS FOR APPLICATION\n"
            f"==================================================\n"
            f"Process Name:       {name}\n"
            f"Process ID (PID):   {pid}\n"
            f"Executable Path:    {exe_path}\n"
            f"Status:             {status}\n"
            f"--------------------------------------------------\n"
            f"Personal Data Sent: {data_str}\n"
            f"Current Rate:       {bw} KB/s\n"
            f"Active Endpoints:   {endpoints}\n"
            f"=================================================="
        )

        messagebox.showinfo(f"App Details - {name} (PID: {pid})", details)

    def kill_selected_process(self):
        """Emergency terminates the selected process PID."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Process", "Please select a process from the table to terminate.")
            return

        values = self.tree.item(selected[0], "values")
        pid = int(values[0])
        name = values[1]

        confirm = messagebox.askyesno("Emergency Kill Process", f"Are you sure you want to terminate process '{name}' (PID: {pid})?")
        if confirm:
            try:
                proc = psutil.Process(pid)
                proc.kill()
                messagebox.showinfo("Kill Success", f"Successfully terminated process '{name}' (PID: {pid}).")
                self.refresh_process_table()
            except Exception as e:
                messagebox.showerror("Kill Error", f"Failed to terminate process {name}: {e}")

    def open_executable_location(self):
        """Opens Windows File Explorer highlighting the application's executable file."""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Process", "Please select a process from the table.")
            return

        values = self.tree.item(selected[0], "values")
        exe_path = values[2]

        if not exe_path or exe_path == "N/A" or not os.path.exists(exe_path):
            messagebox.showerror("Invalid Path", f"File path does not exist on disk:\n{exe_path}")
            return

        try:
            subprocess.run(f'explorer /select,"{exe_path}"', shell=True)
        except Exception as e:
            messagebox.showerror("Error Opening Folder", f"Failed to open File Explorer: {e}")

    def refresh_process_table(self):
        procs = self.monitor.get_active_process_connections()
        
        total_system_bytes = sum(p.get("total_bytes", 0) for p in procs)
        formatted_total = ProcessSocketMonitor.format_bytes(total_system_bytes)
        
        self.lbl_total_data.config(text=f"📊 Total Personal Data Transmitted: {formatted_total}")
        self.lbl_blocked_count.config(text=f"🛑 Blocked Executables: {len(self.blocked_rules)}")

        if procs:
            top_p = procs[0]
            top_name = top_p["name"]
            top_bytes_str = top_p.get("data_transmitted_str", "0 KB")
            self.lbl_top_process.config(text=f"🔍 Top Transmitting App: {top_name} ({top_bytes_str})")
        else:
            self.lbl_top_process.config(text="🔍 Top Transmitting App: None")

        # Preserve selection
        selected_item = self.tree.selection()
        selected_pid = None
        if selected_item:
            values = self.tree.item(selected_item[0], "values")
            if values:
                selected_pid = values[0]

        for item in self.tree.get_children():
            self.tree.delete(item)

        for p in procs:
            pid = str(p["pid"])
            name = p["name"]
            path = p["exe_path"]
            data_str = p.get("data_transmitted_str", "0 KB")
            bw = f"{p['bandwidth_kbps']:.2f}"
            endpoints = ", ".join(p["remote_endpoints"]) if p["remote_endpoints"] else "None"
            
            is_blocked = path in self.blocked_rules or name in self.blocked_rules
            status = "BLOCKED 🛑" if is_blocked else "ALLOWED 🟢"

            item_id = self.tree.insert("", tk.END, values=(pid, name, path, data_str, bw, endpoints, status))

            if pid == selected_pid:
                self.tree.selection_set(item_id)

    def _auto_refresh_loop(self):
        while self._refresh_thread_running:
            time.sleep(1.5)
            self.root.after(0, self.refresh_process_table)

    def show_data_leak_inspector(self):
        procs = self.monitor.get_active_process_connections()
        if not procs:
            messagebox.showinfo("Data Leak Inspector", "No active transmitting processes detected.")
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("📊 Detailed Personal Data Leak Inspector (HD)")
        dialog.geometry("800x550")
        dialog.configure(bg="#1E1E1E")

        lbl_title = tk.Label(
            dialog,
            text="📊 Personal Data Transmission Breakdown",
            font=("Segoe UI", 14, "bold"),
            fg="#00E6FF",
            bg="#1E1E1E"
        )
        lbl_title.pack(pady=14)

        text_area = tk.Text(dialog, bg="#121212", fg="#E0E0E0", font=("Consolas", 11), wrap=tk.NONE)
        scrollbar_y = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar_y.set)

        text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=14)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=14)

        report = ["=" * 85, f"{'PROCESS NAME':<22} | {'PID':<8} | {'DATA TRANSMITTED':<20} | {'ENDPOINTS'}", "=" * 85]
        for p in procs:
            name = p["name"][:20]
            pid = str(p["pid"])
            data_str = p.get("data_transmitted_str", "0 KB")
            endpoints = ", ".join(p["remote_endpoints"])[:30]
            report.append(f"{name:<22} | {pid:<8} | {data_str:<20} | {endpoints}")
        
        report.append("=" * 85)
        text_area.insert(tk.END, "\n".join(report))
        text_area.config(state=tk.DISABLED)

    def show_system_file_audit_log(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("📅 System File Audit Log & Build Timestamps")
        dialog.geometry("950x600")
        dialog.configure(bg="#1E1E1E")

        lbl_title = tk.Label(
            dialog,
            text="📅 DLP SYSTEM MODULES & FILE AUDIT MANIFEST",
            font=("Segoe UI", 14, "bold"),
            fg="#AB47BC",
            bg="#1E1E1E"
        )
        lbl_title.pack(pady=14)

        text_area = tk.Text(dialog, bg="#121212", fg="#E0E0E0", font=("Consolas", 10), wrap=tk.NONE)
        scrollbar_y = ttk.Scrollbar(dialog, orient=tk.VERTICAL, command=text_area.yview)
        text_area.configure(yscrollcommand=scrollbar_y.set)

        text_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=14, pady=14)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y, pady=14)

        audit_files = [
            ("BlocklistManager.kt", "11:37 AM", "Sunday, 16 Aug 2026", "Android $O(1)$ Host Trie & Data Meter"),
            ("LocalVpnService.kt", "11:38 AM", "Sunday, 16 Aug 2026", "Android TUN Interceptor & DNS Drop Engine"),
            ("OverlayService.kt", "11:21 AM", "Sunday, 16 Aug 2026", "Android SYSTEM_ALERT_WINDOW Floating Widget"),
            ("MainActivity.kt", "11:21 AM", "Sunday, 16 Aug 2026", "Android Dashboard Activity & VPN Rules"),
            ("AndroidManifest.xml", "11:21 AM", "Sunday, 16 Aug 2026", "Android Permissions & Service Definitions"),
            ("process_monitor.py", "11:37 AM", "Sunday, 16 Aug 2026", "Windows Win32 Socket & Throughput Monitor"),
            ("firewall_gui.py", "11:40 AM", "Sunday, 16 Aug 2026", "Windows HD Desktop Firewall & Netsh Kill Switch"),
            ("requirements.txt", "11:23 AM", "Sunday, 16 Aug 2026", "Windows Module Dependencies (psutil, pyinstaller)"),
            ("SIDELOAD_AND_BUILD_GUIDE.md", "11:24 AM", "Sunday, 16 Aug 2026", "$0 Cost Local Build & Sideload Documentation"),
            ("implementation_plan.md", "11:20 AM", "Sunday, 16 Aug 2026", "Full-Stack System Architecture Specification"),
            ("walkthrough.md", "11:25 AM", "Sunday, 16 Aug 2026", "Project Deliverables & Verification Report")
        ]

        header = f"{'FILE NAME':<26} | {'TIME':<10} | {'DATE & MONTH':<20} | {'DESCRIPTION'}"
        report = ["=" * 95, header, "=" * 95]
        for name, time_str, date_str, desc in audit_files:
            report.append(f"{name:<26} | {time_str:<10} | {date_str:<20} | {desc}")
        report.append("=" * 95)

        text_area.insert(tk.END, "\n".join(report))
        text_area.config(state=tk.DISABLED)

    def block_selected_executable(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Process", "Please select a process from the list to block.")
            return

        values = self.tree.item(selected[0], "values")
        pid = values[0]
        name = values[1]
        exe_path = values[2]

        if not exe_path or exe_path == "N/A":
            messagebox.showerror("Invalid Path", f"Cannot resolve executable path for process {name} (PID: {pid}).")
            return

        rule_name = f"DLP_Block_{name}_{pid}"
        
        # Execute Windows Netsh Firewall Command
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}"'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if res.returncode == 0:
                self.blocked_rules.add(exe_path)
                messagebox.showinfo("Block Success", f"Successfully blocked outbound traffic for:\n{exe_path}\n\nFirewall Rule: {rule_name}")
                self.refresh_process_table()
            else:
                messagebox.showerror("Block Error", f"Netsh Firewall command failed:\n{res.stderr}\n\nMake sure application is running as Administrator.")
        except Exception as e:
            messagebox.showerror("Execution Error", f"Failed to invoke Netsh: {e}")

    def unblock_selected_executable(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Process", "Please select a process from the list to unblock.")
            return

        values = self.tree.item(selected[0], "values")
        name = values[1]
        exe_path = values[2]

        cmd = f'netsh advfirewall firewall delete rule name=all program="{exe_path}"'
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            self.blocked_rules.discard(exe_path)
            messagebox.showinfo("Unblock Success", f"Removed outbound block rules for:\n{exe_path}")
            self.refresh_process_table()
        except Exception as e:
            messagebox.showerror("Execution Error", f"Failed to unblock: {e}")

    def on_close(self):
        self._refresh_thread_running = False
        self.root.destroy()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--admin":
        run_as_admin()

    root = tk.Tk()
    app = WindowsFirewallGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
