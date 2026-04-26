import tkinter as tk
from tkinter import messagebox
import os
import platform
import sys
import ctypes
from urllib.parse import urlparse
import threading
import requests
import time
from datetime import datetime 

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if platform.system() == "Windows":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join([f'"{sys.argv[0]}"'] + sys.argv[1:]), None, 1)
        sys.exit()

REDIRECT_IP = "127.0.0.1"


LOG_FILE = "log.txt"

VT_API_KEY = "YOUR_API_KEY"
VT_HEADERS = {"x-apikey": VT_API_KEY}


def log_action(action):
    """Logs an action with a timestamp to the log file."""
  
    with open(LOG_FILE, "a") as log:
        log.write(f"[{datetime.now()}] {action}\n")

def get_hosts_path():
    """Returns the path to the hosts file based on the OS."""
    os_name = platform.system()
    if os_name == "Windows":
        return r"C:\Windows\System32\drivers\etc\hosts"
    elif os_name in ["Linux", "Darwin"]:
        return "/etc/hosts"
    else:
        raise Exception("Unsupported OS: " + os_name)

def extract_domain(url):
    """Extracts the domain name from a URL."""
    if not url.strip():
        return None
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url 
    domain = urlparse(url).hostname
    return domain



def vt_scan_url(url):
    """Submits a URL to VirusTotal for scanning and waits for results."""
    try:
       
        response = requests.post("https://www.virustotal.com/api/v3/urls", headers=VT_HEADERS, data={"url": url})
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]


        for _ in range(5): 
            time.sleep(4)
            r = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=VT_HEADERS)
            r.raise_for_status()
            result = r.json()["data"]
            if result["attributes"]["status"] == "completed": 
                return result["attributes"]["stats"]
        return {"error": "Scan timed out."} 
    except requests.exceptions.RequestException as e:
        
        return {"error": f"Network/API Error: {e}"}
    except Exception as e:
        
        return {"error": f"An unexpected error occurred: {e}"}

def scan_and_display():
    """Initiates VirusTotal scan and displays results, auto-blocking if malicious."""
    url = website_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a website URL.")
        return

    messagebox.showinfo("VirusTotal Scan", "Scanning... Please wait.")
    
    threading.Thread(target=show_vt_result, args=(url,), daemon=True).start()

def show_vt_result(url):
    """Displays VirusTotal scan results and handles auto-blocking."""
    stats = vt_scan_url(url) 

    if "error" in stats:
        messagebox.showerror("VirusTotal Error", stats["error"])
        return

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)

    
    verdict_message = f"VirusTotal verdict for {url}\n\n"
    for key, val in stats.items():
        verdict_message += f"{key.capitalize():<12}: {val}\n"

    
    if malicious > 0 or suspicious > 0:
        verdict_message += "\n⚠️ Website flagged as potentially harmful.\nAutomatically blocking it..."
    
        block_websites([url])
        log_action(f"Auto-blocked {url} due to VirusTotal verdict (malicious:{malicious}, suspicious:{suspicious})")
    else:
        verdict_message += "\n✅ Website appears clean."

    messagebox.showinfo("VirusTotal Result", verdict_message)



def block_websites(urls):
    """Adds website domains to the hosts file to block them."""

  
    domains_to_block = list(set(filter(None, [extract_domain(u) for u in urls])))
    if not domains_to_block:
        messagebox.showwarning("Input Error", "No valid domains found to block.")
        return

    try:
        hosts_path = get_hosts_path()

        with open(hosts_path, "a") as file:
            for domain in domains_to_block:
                entry = f"\n{REDIRECT_IP}\t{domain}" 
                file.write(entry)
                log_action(f"Blocked: {domain}")
        messagebox.showinfo("Success", "Websites Blocked Successfully.")
        refresh_blocked_list() 
    except PermissionError:

        messagebox.showerror("Permission Error", "Administrator privileges required.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def unblock_websites(urls):
    """Removes website domains from the hosts file to unblock them."""

    domains_to_unblock = list(set(filter(None, [extract_domain(u) for u in urls])))
    if not domains_to_unblock:
        messagebox.showwarning("Input Error", "No valid domains found to unblock.")
        return

    try:
        hosts_path = get_hosts_path()
      
        with open(hosts_path, "r") as file:
            lines = file.readlines()


        new_lines = [line for line in lines if not any(domain in line for domain in domains_to_unblock)]
        
        
        with open(hosts_path, "w") as file:
            file.writelines(new_lines)
            
        for domain in domains_to_unblock:
            log_action(f"Unblocked: {domain}")

        messagebox.showinfo("Success", "Websites Unblocked Successfully.")
        refresh_blocked_list() 
    except PermissionError:
        messagebox.showerror("Permission Error", "Administrator privileges required.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def get_blocked_sites():
    """Reads the hosts file and returns currently blocked sites by this app."""
    try:
    
        with open(get_hosts_path(), "r") as file:
            return [line.strip() for line in file.readlines() if line.strip() and line.startswith(REDIRECT_IP)]
    except FileNotFoundError:
        return [] 
    except Exception:
        return [] 

def refresh_blocked_list():
    """Updates the displayed list of blocked sites."""
    listbox.delete(0, tk.END) 
    for site in get_blocked_sites():
        listbox.insert(tk.END, site)



def submit_block():
    """Handles blocking a single URL from the entry field."""

    block_websites([website_entry.get()])

def submit_unblock():
    """Handles unblocking a single URL from the entry field."""
    
    unblock_websites([website_entry.get()])



app = tk.Tk()
app.title("Simple Website Blocker") 
app.geometry("500x450")

tk.Label(app, text="Website URL:").pack(pady=5)
website_entry = tk.Entry(app, width=50)
website_entry.pack()


button_frame = tk.Frame(app)
button_frame.pack(pady=10)


tk.Button(button_frame, text="Block Website", command=submit_block).grid(row=0, column=0, padx=5, pady=5)

tk.Button(button_frame, text="Unblock Website", command=submit_unblock).grid(row=0, column=1, padx=5, pady=5)

tk.Button(button_frame, text="Scan with VirusTotal", command=scan_and_display).grid(row=1, column=0, columnspan=2, pady=5)

tk.Label(app, text="Currently Blocked Sites:").pack(pady=10)

listbox = tk.Listbox(app, width=60, height=8)
listbox.pack()


refresh_blocked_list()

app.mainloop() 