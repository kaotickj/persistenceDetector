import tkinter.font as tkFont
import tkinter as tk
from tkinter import messagebox
import winreg
import base64
import re
import string

class RegistryCheckerApp:
    def __init__(self, root):
        # setting title
        root.title("Registry Persistence Detector")
        #setting window size
        width=600
        height=400
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

        output_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=11)
        output_label["font"] = ft
        output_label["fg"] = "#333333"
        output_label["justify"] = "center"
        output_label["text"] = "Results: "
        output_label.place(x=20,y=100,width=70,height=25)

        self.output_text=tk.Text(root)
        ft = tkFont.Font(family='Times',size=11)
        self.output_text["font"] = ft
        self.output_text["fg"] = "#333333"
        self.output_text.place(x=10,y=130,width=574,height=200)

        check_button=tk.Button(root)
        check_button["bg"] = "#e9e9ed"
        ft = tkFont.Font(family='Times',size=11)
        check_button["font"] = ft
        check_button["fg"] = "#000000"
        check_button["justify"] = "center"
        check_button["text"] = "Check Registry"
        check_button.place(x=240,y=340,width=110,height=25)
        check_button["command"] = self.check_registry

        options_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=11)
        options_label["font"] = ft
        options_label["fg"] = "#333333"
        options_label["justify"] = "center"
        options_label["text"] = "Scan Options :"
        options_label.place(x=20,y=30,width=90,height=25)

        options_powershell=tk.Checkbutton(root)
        ft = tkFont.Font(family='Times',size=11)
        options_powershell["font"] = ft
        options_powershell["fg"] = "#333333"
        options_powershell["justify"] = "center"
        options_powershell["text"] = "Powershell Commands"
        options_powershell.place(x=80,y=60,width=170,height=25)
        options_powershell["offvalue"] = "1"
        options_powershell["onvalue"] = "0"
        options_powershell["command"] = self.options_powershell_command

        options_encoded=tk.Checkbutton(root)
        ft = tkFont.Font(family='Times',size=11)
        options_encoded["font"] = ft
        options_encoded["fg"] = "#333333"
        options_encoded["justify"] = "center"
        options_encoded["text"] = "Encoded Payloads"
        options_encoded.place(x=320,y=60,width=170,height=25)
        options_encoded["offvalue"] = "1"
        options_encoded["onvalue"] = "0"
        options_encoded["command"] = self.options_encoded_command

    def check_registry(self):
        self.output_text.delete(1.0, tk.END)
        malicious_entries = self.get_malicious_entries()
        if malicious_entries:
            self.output_text.insert(tk.END, "Malicious registry persistence detected:\n\n")
            for entry in malicious_entries:
                self.output_text.insert(tk.END, f"Location: {entry[0]}, Name: {entry[1]}, Data: {entry[2]}\n\n")

            # Alert the user
            alert_message = "Malicious registry persistence detected. Please review the output.\n"
            alert_message += "To delete the found keys, follow these steps:\n"
            alert_message += "1. Press Win + R, type 'regedit', and press Enter to open the Registry Editor.\n"
            alert_message += "2. Navigate to the location mentioned in the output.\n"
            alert_message += "3. Right-click on the malicious key and select 'Delete'.\n"
            alert_message += "4. Confirm the deletion if prompted.\n"
            messagebox.showwarning("Alert", alert_message)


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
            ]),
            (winreg.HKEY_USERS, [
                r"S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Run",
                # Add more locations as needed based on your analysis
            ]),
            (winreg.HKEY_USERS, [
                r"S-1-5-19\Software\Microsoft\Windows\CurrentVersion\Run",
                # Add more locations as needed based on your analysis
            ]),
            # Add more user keys as needed
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

    def options_powershell_command(self):
        self.output_text.insert(tk.END, "Scan for Powershell Commands Enabled\n")

    def options_encoded_command(self):
        self.output_text.insert(tk.END, "Scan for Encoded Commands Enabled\n")

    def show_about(self):
        messagebox.showinfo("About", "This application is developed by Kaotick Jay for detecting and remediating malicious registry persistence.")

    def show_help(self):
        messagebox.showinfo("Help", "To use this application, simply click the 'Check Registry' button to detect any malicious registry persistence.")

if __name__ == "__main__":
    root = tk.Tk()
    app = RegistryCheckerApp(root)
    root.mainloop()
