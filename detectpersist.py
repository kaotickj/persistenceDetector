# detectpersist.py

import tkinter.font as tkFont
import tkinter as tk
from tkinter import messagebox
import tkinter.filedialog as filedialog
import winreg
import base64
import re
import string
from datetime import datetime
import webbrowser
from tkinter import ttk
import sys
import ctypes

def is_user_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if is_user_admin():
        messagebox.showinfo("Admin Check", "The application is already running with Administrator privileges.")
        return

    params = " ".join([f'"{arg}"' for arg in sys.argv])
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        sys.exit(0)  # Exit current instance after launching elevated
    except Exception as e:
        messagebox.showerror("Elevation Failed", f"Failed to elevate privileges:\n{e}")

class RegistryCheckerApp:
    def __init__(self, root):
        root.title("Registry Persistence Detector")
        width = 600
        height = 450
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        menubar = tk.Menu(root)
        root.config(menu=menubar)

        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Menu", menu=file_menu)
        file_menu.add_command(label="About", command=self.show_about)
        file_menu.add_command(label="Help", command=self.show_help)
        file_menu.add_command(label="Instructions", command=self.show_instructions)
        file_menu.add_separator()
        file_menu.add_command(label="Run as Administrator", command=self.run_as_admin_command)

        menubar.add_command(label="Donate", command=self.show_donate_dialog)

        output_label = tk.Label(root)
        ft = tkFont.Font(family='Times', size=11)
        output_label["font"] = ft
        output_label["fg"] = "#333333"
        output_label["justify"] = "center"
        output_label["text"] = "Results: "
        output_label.place(x=20, y=100, width=70, height=25)

        self.output_text = tk.Text(root)
        self.output_text["font"] = ft
        self.output_text["fg"] = "#333333"
        self.output_text.place(x=10, y=130, width=574, height=200)

        check_button = tk.Button(root)
        check_button["bg"] = "#e9e9ed"
        check_button["font"] = ft
        check_button["fg"] = "#000000"
        check_button["justify"] = "center"
        check_button["text"] = "Check Registry"
        check_button.place(x=240, y=340, width=110, height=25)
        check_button["command"] = self.check_registry

        options_label = tk.Label(root)
        options_label["font"] = ft
        options_label["fg"] = "#333333"
        options_label["justify"] = "center"
        options_label["text"] = "Scan Options :"
        options_label.place(x=20, y=30, width=90, height=25)

        # Variables for checkbuttons (1 = enabled, 0 = disabled)
        self.powershell_var = tk.IntVar(value=1)
        self.encoded_var = tk.IntVar(value=1)

        options_powershell = tk.Checkbutton(root, variable=self.powershell_var)
        options_powershell["font"] = ft
        options_powershell["fg"] = "#333333"
        options_powershell["justify"] = "center"
        options_powershell["text"] = "Powershell Commands"
        options_powershell.place(x=80, y=60, width=170, height=25)
        options_powershell["command"] = self.options_powershell_command

        options_encoded = tk.Checkbutton(root, variable=self.encoded_var)
        options_encoded["font"] = ft
        options_encoded["fg"] = "#333333"
        options_encoded["justify"] = "center"
        options_encoded["text"] = "Encoded Payloads"
        options_encoded.place(x=320, y=60, width=170, height=25)
        options_encoded["command"] = self.options_encoded_command

        self.registry_view_var = tk.StringVar()
        self.registry_view_combo = ttk.Combobox(root, textvariable=self.registry_view_var, state="readonly")
        self.registry_view_combo["values"] = ("64-bit", "32-bit")
        self.registry_view_combo.current(0)
        arch_label = tk.Label(root)
        arch_label["font"] = ft
        arch_label["fg"] = "#333333"
        arch_label["justify"] = "left"
        arch_label["text"] = "Registry View:"
        arch_label.place(x=320, y=30, width=90, height=25)
        self.registry_view_combo.place(x=420, y=30, width=110, height=25)

        self.combo_box = ttk.Combobox(root, state="readonly")
        self.combo_box["font"] = tkFont.Font(family='Times', size=10)
        self.combo_box.place(x=10, y=380, width=400, height=25)

        delete_button = tk.Button(root)
        delete_button["bg"] = "#e9e9ed"
        delete_button["font"] = ft
        delete_button["fg"] = "#000000"
        delete_button["justify"] = "center"
        delete_button["text"] = "Delete Selected"
        delete_button.place(x=420, y=380, width=110, height=25)
        delete_button["command"] = self.delete_selected_key

        self.malicious_entries = []

        # Notify user of privilege level on startup
        if is_user_admin():
            self.output_text.insert(tk.END, "[*] Running with Administrator privileges.\n")
        else:
            self.output_text.insert(tk.END,
                "[*] Running without Administrator privileges. Some keys may be inaccessible.\n"
                "    To elevate privileges, choose 'Run as Administrator' from the Menu.\n"
            )

        # Output initial scan option states
        self.output_text.insert(tk.END,
            f"Scan for Powershell Commands {'Enabled' if self.powershell_var.get() else 'Disabled'}\n"
            f"Scan for Encoded Payloads {'Enabled' if self.encoded_var.get() else 'Disabled'}\n"
        )

    def run_as_admin_command(self):
        run_as_admin()

    def show_instructions(self):
        instruction_win = tk.Toplevel()
        instruction_win.title("Instructions")
        instruction_win.geometry("600x400")
        instruction_win.resizable(False, False)

        ft = tkFont.Font(family='Times', size=11)
        label = tk.Label(
            instruction_win,
            text=(
                "USAGE INSTRUCTIONS:\n\n"
                "1. Click 'Check Registry' to scan for suspicious entries.\n"
                "2. Check or uncheck options for encoded payloads and PowerShell detection.\n"
                "3. Select 'Registry View' from the dropdown:\n"
                "   - On 32-bit systems: Only '32-bit' is needed and used.\n"
                "   - On 64-bit systems: Run a 32-bit scan first, then switch to 64-bit view and scan again.\n"
                "     This is necessary because 64-bit Windows maintains separate registry views for 32-bit\n"
                "     and 64-bit applications. Both may be used by malware to achieve persistence.\n\n"
                "4. Results will be shown in the output panel. If malicious entries are detected,\n"
                "   you may delete them after optionally backing up the value.\n\n"
                "For guidance on analyzing the results and removing other types of persistence beyond the scope of this tool,"
                " please consult my comprehensive guide:"
            ),
            font=ft, wraplength=580, justify="left"
        )
        label.pack(pady=(10, 5), padx=10)

        link = tk.Label(
            instruction_win,
            text="Detecting Persistence on Windows for Non-Technical Users",
            font=ft, fg="blue", cursor="hand2"
        )
        link.pack()
        link.bind(
            "<Button-1>",
            lambda e: webbrowser.open_new(
                "https://github.com/kaotickj/Detecting-Persistence-on-Windows-Computers-for-Non-Technical-Users"
            )
        )

        tk.Button(instruction_win, text="Close", command=instruction_win.destroy).pack(pady=(10, 10))

    def show_about(self):
        about_win = tk.Toplevel()
        about_win.title("About")
        about_win.geometry("400x150")
        about_win.resizable(False, False)

        ft = tkFont.Font(family='Times', size=11)
        label1 = tk.Label(about_win, text="This application is developed by Kaotick Jay", font=ft)
        label1.pack(pady=(10, 5))

        label2 = tk.Label(about_win, text="Project GitHub Repository:", font=ft)
        label2.pack()

        link = tk.Label(about_win, text="https://github.com/kaotickj/persistenceDetector",
                        font=ft, fg="blue", cursor="hand2")
        link.pack()
        link.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/kaotickj/persistenceDetector"))

        close_btn = tk.Button(about_win, text="Close", command=about_win.destroy)
        close_btn.pack(pady=(10, 10))

    def show_help(self):
        messagebox.showinfo("Help", "To use this application, simply click the 'Check Registry' button to detect any malicious registry persistence.")

    def show_donate_dialog(self):
        donate_win = tk.Toplevel()
        donate_win.title("Donate")
        donate_win.geometry("400x180")
        donate_win.resizable(False, False)

        ft = tkFont.Font(family='Times', size=11)
        label = tk.Label(donate_win, text="Thank you for considering a donation to support ongoing development and maintenance. Please choose an option below for processing your donation.", font=ft, wraplength=380, justify="left")
        label.pack(pady=(10, 5), padx=10)

        def make_link(parent, text, url):
            link = tk.Label(parent, text=text, font=ft, fg="blue", cursor="hand2")
            link.pack(anchor='w', padx=10)
            link.bind("<Button-1>", lambda e: webbrowser.open_new(url))
            return link

        make_link(donate_win, " GitHub: @kaotickj", "https://github.com/sponsors/kaotickj")
        make_link(donate_win, " Patreon: KaotickJay", "https://patreon.com/KaotickJay")
        make_link(donate_win, " PayPal: Donate Here", "https://paypal.me/kaotickj")

        tk.Button(donate_win, text="Close", command=donate_win.destroy).pack(pady=(10, 10))

    def options_powershell_command(self):
        state = "Enabled" if self.powershell_var.get() else "Disabled"
        self.output_text.insert(tk.END, f"Scan for Powershell Commands {state}\n")

    def options_encoded_command(self):
        state = "Enabled" if self.encoded_var.get() else "Disabled"
        self.output_text.insert(tk.END, f"Scan for Encoded Payloads {state}\n")

    def check_registry(self):
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END,
            f"Scan for Powershell Commands {'Enabled' if self.powershell_var.get() else 'Disabled'}\n"
            f"Scan for Encoded Payloads {'Enabled' if self.encoded_var.get() else 'Disabled'}\n\n"
        )
        self.malicious_entries = self.get_malicious_entries()
        if self.malicious_entries:
            self.output_text.insert(tk.END, "Malicious registry persistence detected:\n\n")
            for entry in self.malicious_entries:
                self.output_text.insert(tk.END, f"Location: {entry[1]}, Name: {entry[2]}, Data: {entry[3]}\n\n")

            display_items = [
                f"{[k for k, v in winreg.__dict__.items() if v == e[0] and k.startswith('HKEY_')][0]}\\{e[1]} → {e[2]}"
                for e in self.malicious_entries
            ]
            self.combo_box["values"] = display_items
            if display_items:
                self.combo_box.current(0)

            messagebox.showwarning("Alert",
                "Malicious registry persistence detected. Please review the output.\n"
                "You may select a key from the dropdown and delete it safely.\n"
                "Backup is prompted before deletion."
            )
        else:
            self.output_text.insert(tk.END, "No malicious registry persistence found.\n")
            self.combo_box.set('')
            self.combo_box["values"] = []

    def get_malicious_entries(self):
        view_flag = winreg.KEY_READ
        selected_view = self.registry_view_var.get()
        if selected_view == "32-bit":
            view_flag |= winreg.KEY_WOW64_32KEY
        else:
            view_flag |= winreg.KEY_WOW64_64KEY

        persistence_locations = [
            (winreg.HKEY_CURRENT_USER, [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Internet Explorer\Extensions",
            ]),
            (winreg.HKEY_LOCAL_MACHINE, [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"System\CurrentControlSet\Services",
                r"Software\Microsoft\Internet Explorer\Extensions",
            ]),
            (winreg.HKEY_CLASSES_ROOT, [
                r"Directory\Background\ShellEx\ContextMenuHandlers",
            ]),
            (winreg.HKEY_USERS, [
                r"S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Run",
                r"S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Run",
            ]),
        ]

        malicious_entries = []

        for root_key, locations in persistence_locations:
            for location in locations:
                try:
                    with winreg.OpenKey(root_key, location, 0, view_flag) as key:
                        num_values = winreg.QueryInfoKey(key)[1]
                        for i in range(num_values):
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            if self.is_malicious(value_name, value_data):
                                malicious_entries.append((root_key, location, value_name, value_data))
                except Exception as e:
                    print(f"Error accessing registry location {location}: {e}")

        return malicious_entries

    def is_malicious(self, value_name, value_data):
        # Basic keyword check first
        if re.search(r"malware|virus|trojan|keylogger", str(value_name), re.IGNORECASE) or \
           re.search(r"malware|virus|trojan|keylogger", str(value_data), re.IGNORECASE):
            return True

        # Check encoded payload only if option enabled
        if self.encoded_var.get():
            if self.is_base64_encoded(str(value_data)):
                return True

        # Check powershell commands only if option enabled
        if self.powershell_var.get():
            if self.is_powershell_command(str(value_data)):
                return True

        return False

    def is_powershell_command(self, data):
        return bool(re.search(r"powershell|-enc", data, re.IGNORECASE))

    def is_base64_encoded(self, data):
        try:
            decoded_data = base64.b64decode(data)
            return all(chr(byte) in string.printable for byte in decoded_data)
        except Exception:
            return False

    def delete_selected_key(self):
        idx = self.combo_box.current()
        if idx < 0:
            messagebox.showinfo("No Selection", "Please select an entry to delete.")
            return

        root_handle, path, name, data = self.malicious_entries[idx]

        backup = messagebox.askyesno("Backup Registry Value", f"Do you want to backup the registry value '{name}' before deletion?")
        if backup:
            export_path = filedialog.asksaveasfilename(
                title="Save Registry Backup",
                defaultextension=".reg",
                filetypes=[("Registry files", "*.reg"), ("All files", "*.*")]
            )
            if not export_path:
                messagebox.showinfo("Backup Cancelled", "Backup cancelled. Deletion aborted.")
                return

            success = self.export_registry_value(root_handle, path, name, export_path)
            if not success:
                return

        view_flag = winreg.KEY_SET_VALUE
        if self.registry_view_var.get() == "32-bit":
            view_flag |= winreg.KEY_WOW64_32KEY
        else:
            view_flag |= winreg.KEY_WOW64_64KEY

        try:
            with winreg.OpenKey(root_handle, path, 0, view_flag) as key:
                winreg.DeleteValue(key, name)

            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.output_text.insert(tk.END, f"[{timestamp}] Deleted: {name} from {path}\n")

            del self.malicious_entries[idx]

            if self.malicious_entries:
                display_items = [
                    f"{[k for k, v in winreg.__dict__.items() if v == e[0] and k.startswith('HKEY_')][0]}\\{e[1]} → {e[2]}"
                    for e in self.malicious_entries
                ]
                self.combo_box["values"] = display_items
                self.combo_box.current(0)
            else:
                self.output_text.insert(tk.END, "\nAll malicious registry entries removed. Rechecking...\n")
                self.check_registry()

        except PermissionError:
            messagebox.showerror("Error", "Permission denied. Please run as Administrator.")
        except FileNotFoundError:
            self.output_text.insert(tk.END, f"Entry '{name}' already removed.\n")
            del self.malicious_entries[idx]
            self.delete_selected_key()
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")

    def export_registry_value(self, root_handle, key_path, value_name, export_path):
        try:
            view_flag = winreg.KEY_READ
            if self.registry_view_var.get() == "32-bit":
                view_flag |= winreg.KEY_WOW64_32KEY
            else:
                view_flag |= winreg.KEY_WOW64_64KEY

            with winreg.OpenKey(root_handle, key_path, 0, view_flag) as key:
                value, val_type = winreg.QueryValueEx(key, value_name)

            hive_name = [k for k, v in winreg.__dict__.items() if v == root_handle and k.startswith("HKEY_")][0]

            reg_content = "Windows Registry Editor Version 5.00\n\n"
            reg_content += f"[{hive_name}\\{key_path}]\n"

            if val_type == winreg.REG_SZ:
                reg_content += f"\"{value_name}\"=\"{value}\"\n"
            elif val_type == winreg.REG_EXPAND_SZ:
                reg_content += f"\"{value_name}\"=hex(2):" + ",".join(f"{b:02x}" for b in value.encode('utf-16le')) + "\n"
            elif val_type == winreg.REG_DWORD:
                reg_content += f"\"{value_name}\"=dword:{value:08x}\n"
            elif val_type == winreg.REG_BINARY:
                reg_content += f"\"{value_name}\"=hex:" + ",".join(f"{b:02x}" for b in value) + "\n"
            else:
                reg_content += f"\"{value_name}\"=hex:" + ",".join(f"{b:02x}" for b in value) + "\n"

            with open(export_path, "w", encoding="utf-8") as f:
                f.write(reg_content)
            return True
        except Exception as e:
            messagebox.showerror("Backup Error", f"Failed to backup registry value:\n{e}")
            return False

if __name__ == "__main__":
    root = tk.Tk()
    app = RegistryCheckerApp(root)
    root.mainloop()
