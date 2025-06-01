import os
import hashlib
import requests
from dotenv import load_dotenv
from colorama import init, Fore

load_dotenv()
init(autoreset=True)

VT_API_KEY = os.getenv("VT_API_KEY")

if not VT_API_KEY:
    print(Fore.RED + "[X] VirusTotal API key missing! Add it to your `.env` file.")
    exit()

suspicious_files = []

def hash_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None

def check_virustotal(hash_value):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            positives = data['data']['attributes']['last_analysis_stats']['malicious']
            return positives
        else:
            return None
    except:
        return None

def scan_drive(path="C:\\"):
    print(Fore.CYAN + f"[+] Scanning ALL folders on {path} (Windows included)...\n")
    count = 1

    for root, dirs, files in os.walk(path, topdown=True):
        for name in files:
            try:
                full_path = os.path.join(root, name)

                if not os.path.isfile(full_path):
                    continue

                file_hash = hash_file(full_path)
                if file_hash is None:
                    continue

                positives = check_virustotal(file_hash)

                if positives is not None and positives > 0:
                    print(Fore.RED + f"[{count}] {full_path} → VT Flags: {positives}")
                    suspicious_files.append(full_path)
                    count += 1

                # Manual sus check (based on name/extensions)
                elif any(ext in name.lower() for ext in ['.exe', '.bat', '.scr', '.ps1']) and "windows" not in full_path.lower():
                    print(Fore.YELLOW + f"[?] Possible sus file: {full_path}")
                    suspicious_files.append(full_path)
                    count += 1

            except Exception as e:
                print(Fore.LIGHTBLACK_EX + f"[!] Skipped: {root} → {str(e)}")

def prompt_delete():
    if not suspicious_files:
        print(Fore.GREEN + "\n[✓] No suspicious files found.")
        return

    print(Fore.MAGENTA + "\n[?] Type:")
    print("    'ALL' to delete all")
    print("    '1,4,6' to delete specific files")
    print("    Or 'N' to cancel")

    choice = input("\n[>>] What do you want to delete? ").strip()

    if choice.lower() == "all":
        for file in suspicious_files:
            try:
                os.remove(file)
                print(Fore.GREEN + f"[✓] Deleted: {file}")
            except Exception as e:
                print(Fore.RED + f"[X] Failed to delete {file} → {str(e)}")
    elif "," in choice:
        nums = [int(x.strip()) for x in choice.split(",") if x.strip().isdigit()]
        for i in nums:
            if 0 < i <= len(suspicious_files):
                try:
                    os.remove(suspicious_files[i-1])
                    print(Fore.GREEN + f"[✓] Deleted: {suspicious_files[i-1]}")
                except Exception as e:
                    print(Fore.RED + f"[X] Failed to delete {suspicious_files[i-1]} → {str(e)}")
    else:
        print(Fore.YELLOW + "[~] No files deleted.")

if __name__ == "__main__":
    scan_drive()
    prompt_delete()
