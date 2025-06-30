import tkinter as tk
from tkinter import messagebox
import winreg
import base64
import re
import string
import win32api
import win32security
import ntsecuritycon


class RegistryCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Malicious Registry Persistence Checker")

        # Menu
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="About", command=self.show_about)
        filemenu.add_command(label="Help", command=self.show_help)
        menubar.add_cascade(label="Menu", menu=filemenu)
        self.root.config(menu=menubar)

        # Input Frame
        self.input_frame = tk.Frame(self.root, padx=10, pady=10)
        self.input_frame.pack()

        # Output Frame
        self.output_frame = tk.Frame(self.root, padx=10, pady=10)
        self.output_frame.pack()

        # Output Textbox
        self.output_text = tk.Text(self.output_frame, height=10, width=50)
        self.output_text.pack()

        # Check Button
        self.check_button = tk.Button(self.input_frame, text="Check Registry", command=self.check_registry)
        self.check_button.pack()

    def check_registry(self):
        malicious_entries = self.get_malicious_entries()
        if malicious_entries:
            self.output_text.insert(tk.END, "Malicious registry persistence detected:\n")
            for entry in malicious_entries:
                self.output_text.insert(tk.END, f"Location: {entry[0]}, Name: {entry[1]}, Data: {entry[2]}\n")

            # Alert the user
            messagebox.showwarning("Alert", "Malicious registry persistence detected. Please review the output.")

            # Implement remediation steps
            self.remediate(malicious_entries)
        else:
            self.output_text.insert(tk.END, "No malicious registry persistence found.\n")

    def get_malicious_entries(self):
        persistence_locations = [
            (winreg.HKEY_CURRENT_USER, [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Internet Explorer\Extensions",
                # Add more locations as needed based on your analysis
            ]),
            (winreg.HKEY_LOCAL_MACHINE, [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"System\CurrentControlSet\Services",
                r"Software\Microsoft\Internet Explorer\Extensions",
                # Add more locations as needed based on your analysis
            ]),
            (winreg.HKEY_CLASSES_ROOT, [
                r"Directory\Background\ShellEx\ContextMenuHandlers",
                # Add more locations as needed based on your analysis
            ])
        ]

        malicious_entries = []

        for root_key, locations in persistence_locations:
            for location in locations:
                try:
                    with winreg.OpenKey(root_key, location, 0, winreg.KEY_READ) as key:
                        num_values = winreg.QueryInfoKey(key)[1]
                        for i in range(num_values):
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            if self.is_malicious(value_name, value_data):
                                malicious_entries.append((location, value_name, value_data))
                except Exception as e:
                    print(f"Error accessing registry location {location}: {e}")

        return malicious_entries

    def is_malicious(self, value_name, value_data):
        # Implement logic to determine if a registry entry is malicious
        if re.search(r"malware|virus|trojan|keylogger", value_name, re.IGNORECASE) or \
                re.search(r"malware|virus|trojan|keylogger", value_data, re.IGNORECASE):
            return True
        if self.is_base64_encoded(value_data):
            return True
        if self.is_powershell_command(value_data):
            return True
        # Add more checks as needed
        return False

    def is_powershell_command(self, data):
        # Check if the data contains PowerShell commands or suspicious strings
        if re.search(r"powershell|-enc", data, re.IGNORECASE):
            return True
        return False

    def is_base64_encoded(self, data):
        try:
            decoded_data = base64.b64decode(data)
            # Check if the decoded data is printable ASCII
            return all(chr(byte) in string.printable for byte in decoded_data)
        except Exception:
            return False

    def remediate(self, malicious_entries):
        # Implement remediation steps to remove or disable malicious entries
        for location, name, _ in malicious_entries:
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, location, 0, winreg.KEY_WRITE)
                if self.registry_value_exists(key, name):
                    # Set permissions on the key to allow modification
                    security_attributes = win32security.SECURITY_ATTRIBUTES()
                    security_attributes.SetSecurityDescriptorDacl(1, None, 0)
                    win32api.RegSetKeySecurity(key.handle, ntsecuritycon.DACL_SECURITY_INFORMATION,
                                               security_attributes.GetSecurityDescriptor())

                    # Delete the registry value
                    winreg.DeleteValue(key, name)
                    self.output_text.insert(tk.END,
                                            f"Remediated: Deleted malicious entry - Location: {location}, Name: {name}\n")
                else:
                    self.output_text.insert(tk.END,
                                            f"Error remediating entry - Location: {location}, Name: {name}: Registry value not found\n")
            except Exception as e:
                self.output_text.insert(tk.END, f"Error remediating entry - Location: {location}, Name: {name}: {e}\n")

    def registry_value_exists(self, key, value_name):
        try:
            winreg.QueryValueEx(key, value_name)
            return True
        except WindowsError:
            return False

    def show_about(self):
        messagebox.showinfo("About", "This application is developed by KaotickJ for detecting and remediating malicious registry persistence.")

    def show_help(self):
        messagebox.showinfo("Help", "To use this application, simply click the 'Check Registry' button to detect any malicious registry persistence.")


if __name__ == "__main__":
    root = tk.Tk()
    app = RegistryCheckerApp(root)
    root.mainloop()
