import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from PIL import Image, ImageTk  # pillow yüklü olmalı
import sys
import ctypes
import os
import time
import hashlib
import uuid
import requests
from pymongo import MongoClient
import pyautogui
import keyboard
import threading
import customtkinter as ctk
import tkinter.messagebox as messagebox
from tkinter import simpledialog


CURRENT_VERSION = "1.1"  # Şu anki sürüm


def hide_console():
    if sys.platform == "win32":
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd != 0:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # gizle

def show_console():
    if sys.platform == "win32":
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd != 0:
            ctypes.windll.user32.ShowWindow(hwnd, 5)  # göster

def download_update(url):
    try:
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            file_path = os.path.realpath(sys.argv[0])
            new_file_path = file_path.replace(".exe", "_new.exe") if file_path.endswith(".exe") else file_path.replace(".py", "_new.py")
            with open(new_file_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            messagebox.showinfo("Güncelleme", "Yeni sürüm indirildi. Uygulama yeniden başlatılıyor.")
            os.startfile(new_file_path)
            sys.exit(0)
        else:
            raise Exception("İndirme başarısız.")
    except Exception as e:
        messagebox.showerror("İndirme Hatası", f"Güncelleme indirilemedi: {e}")
        sys.exit(1)

def loading_screen():
    root = tk.Tk()
    root.title("Yükleniyor...")

    width, height = 500, 300
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width // 2) - (width // 2)
    y = (screen_height // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    root.overrideredirect(True)
    root.resizable(False, False)

    image_path = "background.png"
    if not os.path.exists(image_path):
        print(f"Hata: '{image_path}' dosyası bulunamadı.")
        root.destroy()
        return

    bg_image = Image.open(image_path)
    bg_image = bg_image.resize((width, height), Image.Resampling.LANCZOS)
    bg_photo = ImageTk.PhotoImage(bg_image)

    canvas = tk.Canvas(root, width=width, height=height, highlightthickness=0)
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, image=bg_photo, anchor="nw")

    strip_height = 20
    canvas.create_rectangle(0, height - strip_height, width, height, fill="black", outline="")

    frame = tk.Frame(root, bg="black")
    frame.place(x=0, y=height - strip_height, width=width, height=strip_height)

    style = ttk.Style()
    style.theme_use('clam')
    style.configure("green.Horizontal.TProgressbar", foreground='lime', background='lime', thickness=strip_height)

    progress = ttk.Progressbar(frame, style="green.Horizontal.TProgressbar", orient='horizontal', length=width, mode='determinate')
    progress.pack(fill="both", expand=True)

    # Durum etiketi
    status_label = tk.Label(root, text="Sunucuya bağlanılıyor...", bg="black", fg="white", font=("Arial", 10, "bold"))
    status_label.place(relx=0.5, rely=0.85, anchor="center")

    def check_server():
        try:
            response = requests.get("http://193.106.196.48:25565/check_update", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") != "ok":
                    raise Exception("Geçersiz sunucu durumu.")

                latest_version = data.get("latest_version", CURRENT_VERSION)
                download_url = data.get("")

                if latest_version != CURRENT_VERSION:
                    status_label.config(text=f"Yeni sürüm bulundu: {latest_version}, indiriliyor...")
                    root.update()
                    download_update("http://193.106.196.48:25565/files/Ghaxchatbot.exe")
                    return False
                else:
                    status_label.config(text="Sürüm güncel.")
                    return True
            else:
                raise Exception("Yanıt kodu 200 değil.")
        except Exception as e:
            messagebox.showerror("Bağlantı Hatası", f"Sunucuya bağlanılamadı: {e}")
            root.destroy()
            sys.exit(1)

    def update_progress(value=0):
        if value == 0:
            if not check_server():  # Yeni sürüm varsa uygulama zaten kapanır
                return
        if value > 100:
            root.destroy()
            return
        progress['value'] = value
        root.after(30, update_progress, value + 1)

    update_progress()
    root.mainloop()

def key_system():
    client = MongoClient("mongodb+srv://Velokey:1212Aa1212@velokey.2ldumcl.mongodb.net/?retryWrites=true&w=majority&appName=Velokey")
    db = client["mamimc12"]
    collection = db["duyurular"]

    def get_announcement():
        announcement = collection.find_one({"name": "duyuru"})
        if announcement:
            return announcement.get("message", "Duyuru bulunamadı.")
        return "Duyuru bulunamadı."

    def get_hwid():
        return hashlib.sha256(uuid.getnode().to_bytes(6, 'big')).hexdigest()

    ascii_art = """\x1b[36m
         ██████╗ ██╗  ██╗ █████╗ ██╗  ██╗██╗      █████╗ ██╗   ██╗███╗  ██╗ █████╗ ██╗  ██╗███████╗██████╗ 
        ██╔════╝ ██║  ██║██╔══██╗╚██╗██╔╝██║     ██╔══██╗██║   ██║████╗ ██║██╔══██╗██║  ██║██╔════╝██╔══██╗
        ██║  ██╗ ███████║███████║ ╚███╔╝ ██║     ███████║██║   ██║██╔██╗██║██║  ╚═╝███████║█████╗  ██████╔╝
        ██║  ╚██╗██╔══██║██╔══██║ ██╔██╗ ██║     ██╔══██║██║   ██║██║╚████║██║  ██╗██╔══██║██╔══╝  ██╔══██╗
        ╚██████╔╝██║  ██║██║  ██║██╔╝╚██╗███████╗██║  ██║╚██████╔╝██║ ╚███║╚█████╔╝██║  ██║███████╗██║  ██║
         ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝ ╚════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
    \x1b[0m"""

    os.system('cls')
    for char in ascii_art:
        print(char, end='', flush=True)
        time.sleep(0.002)

    announcement = get_announcement()
    print("\n\x1b[94m          ~          ~          ~          ~          ~          ~          ~          ~          ~          ~\n")
    print(f"\x1b[1m\x1b[32m[DUYURU] \x1b[0m{announcement}\x1b[0m\n")
    time.sleep(1)

    print(" \x1b[0m[ \x1b[36m~ \x1b[0m] \x1b[0m\x1b[1mKey: \x1b[0m", end='')
    key_value = input()

    hwid = get_hwid()

    url = "http://193.106.196.48:25565/login"
    data = {
        "key_value": key_value,
        "hwid": hwid
    }

    try:
        response = requests.post(url, json=data)
    except requests.exceptions.RequestException:
        print("\x1b[31m[!] Sunucuya bağlanılamadı.\x1b[0m")
        time.sleep(1)
        sys.exit(1)

    if response.status_code == 200:
        json_data = response.json()
        message = json_data["message"]
        remaining_days = json_data.get("remaining_days")
        description = json_data.get("description")

        print("\x1b[32m[+] Key anahtar doğrulandı:", message)
        print("\x1b[32m[-] Açıklama:", description)
        print("\x1b[32m[-] Kalan süre:", remaining_days, "gün\n")

        print("\x1b[36m[~] :) \x1b[0m")
        time.sleep(1)
    elif response.status_code == 403:
        print(f"\x1b[31m[!] {response.json().get('message', 'Erişim engellendi.')}\x1b[0m")
        time.sleep(1)
        sys.exit(1)

    elif response.status_code == 401:
        print(f"\x1b[31m[!] Geçersiz anahtar.\x1b[0m")
        time.sleep(1)
        sys.exit(1)

    else:
        print(f"\x1b[31m[!] Beklenmeyen hata: {response.status_code}\x1b[0m")
        time.sleep(1)
        sys.exit(1)

settings_file = "settings.txt"
running = False
messages = []

settings = {
    "delay": 2,
    "loops": 0,
    "theme": "light",
    "start_hotkey": "f10",
    "stop_hotkey": "f9"
}

def load_settings():
    if os.path.exists(settings_file):
        with open(settings_file, "r", encoding="utf-8") as f:
            for line in f:
                if '=' in line:
                    key, val = line.strip().split("=", 1)
                    if key in settings:
                        if key in ["theme", "start_hotkey", "stop_hotkey"]:
                            settings[key] = val
                        else:
                            settings[key] = float(val) if '.' in val else int(val)
    else:
        save_settings()

def save_settings():
    with open(settings_file, "w", encoding="utf-8") as f:
        for key, val in settings.items():
            f.write(f"{key}={val}\n")

def toggle_theme():
    settings["theme"] = "dark" if settings["theme"] == "light" else "light"
    ctk.set_appearance_mode(settings["theme"])
    save_settings()


def apply_theme():
    theme = settings["theme"]
    bg = "#1e1e1e" if theme == "dark" else "#f7f9fb"
    fg = "#ffffff" if theme == "dark" else "#000000"
    entry_bg = "#2e2e2e" if theme == "dark" else "#ffffff"
    list_bg = "#2e2e2e" if theme == "dark" else "#ffffff"
    log_bg = "#2c2c2c" if theme == "dark" else "#f0f0f0"

    root.config(bg=bg)

    for widget in root.winfo_children():
        if isinstance(widget, (tk.Label, tk.Button)):
            widget.config(bg=bg, fg=fg)
        elif isinstance(widget, tk.Frame):
            widget.config(bg=bg)
        elif isinstance(widget, tk.Entry):
            widget.config(bg=entry_bg, fg=fg, insertbackground=fg)
        elif isinstance(widget, tk.Listbox):
            widget.config(bg=list_bg, fg=fg, selectbackground="#666" if theme == "dark" else "#ccc")

        # Frame içindekileri de uygula
        if isinstance(widget, tk.Frame):
            for subwidget in widget.winfo_children():
                try:
                    if isinstance(subwidget, (tk.Label, tk.Button)):
                        subwidget.config(bg=bg, fg=fg)
                    elif isinstance(subwidget, tk.Entry):
                        subwidget.config(bg=entry_bg, fg=fg, insertbackground=fg)
                except:
                    pass

    log_text.config(bg=log_bg, fg=fg, insertbackground=fg)

def add_message():
    msg = message_entry.get()
    if msg.strip():
        messages.append(msg)
        message_entry.delete(0, tk.END)
        update_message_frame()
        log_message(f"Mesaj eklendi: {msg}")
    else:
        messagebox.showwarning("Uyarı", "Mesaj boş olamaz!")


def save_messages():
    try:
        with open("mesajlar.txt", "w", encoding="utf-8") as f:
            for msg in messages:
                f.write(msg + "\n")
        messagebox.showinfo("Kaydedildi", "Mesajlar 'mesajlar.txt' dosyasına kaydedildi.")
    except Exception as e:
        messagebox.showerror("Hata", f"Kaydedilemedi: {e}")

def load_messages():
    global messages
    if not os.path.exists("mesajlar.txt"):
        messagebox.showwarning("Uyarı", "'mesajlar.txt' bulunamadı.")
        return
    with open("mesajlar.txt", "r", encoding="utf-8") as f:
        messages = f.read().splitlines()
    update_message_frame()
    messagebox.showinfo("Yüklendi", "'mesajlar.txt' yüklendi.")


def start_bot():
    global running
    if running:
        return
    if not messages:
        messagebox.showwarning("Uyarı", "En az 1 mesaj eklemelisin.")
        return
    try:
        delay = float(delay_entry.get())
        loops = int(loop_entry.get())
        settings["delay"] = delay
        settings["loops"] = loops
        save_settings()
    except ValueError:
        messagebox.showerror("Hata", "Gecikme ve döngü sayısı sayısal olmalıdır.")
        return
    running = True
    threading.Thread(target=message_loop, args=(delay, loops), daemon=True).start()
    log_message("Bot başlatıldı.")

def stop_bot():
    global running
    if not running:
        messagebox.showinfo("Bilgi", "Bot zaten durdu.")
        return
    running = False
    log_message("Bot durduruldu.")

def log_message(text):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    full_text = f"[{timestamp}] {text}\n"
    try:
        log_text.configure(state='normal')
        log_text.insert("end", full_text)
        log_text.see("end")
        log_text.configure(state='disabled')
    except Exception as e:
        print(f"Log mesajı yazılamadı: {e}")
    with open("chat_log.txt", "a", encoding="utf-8") as f:
        f.write(full_text)

def message_loop(delay, loops):
    global running
    loop_counter = 0
    message_counter = 0
    while running and (loops == 0 or loop_counter < loops):
        for msg in messages:
            if not running:
                break
            pyautogui.press('t')
            time.sleep(0.1)
            upper_msg = msg.upper()
            for char in upper_msg:
                keyboard.write(char)
                time.sleep(0.035)
            time.sleep(0.05)
            pyautogui.press('enter')
            log_message(f"Mesaj gönderildi: {upper_msg}")
            message_counter += 1
            if message_counter % 50 == 0:
                log_message("50 mesaj gönderildi, 60 saniye bekleniyor...")
                time.sleep(60)
            time.sleep(delay)
        loop_counter += 1
    running = False
    log_message("Mesaj döngüsü tamamlandı.")

def update_hotkeys():
    settings["start_hotkey"] = start_hotkey_entry.get().lower()
    settings["stop_hotkey"] = stop_hotkey_entry.get().lower()
    save_settings()
    messagebox.showinfo("Kısayollar Güncellendi", f"Başlat: {settings['start_hotkey']} | Durdur: {settings['stop_hotkey']}")
    restart_hotkey_listener()

hotkey_refs = []

def restart_hotkey_listener():
    global hotkey_refs
    for ref in hotkey_refs:
        keyboard.remove_hotkey(ref)
    hotkey_refs.clear()

    start_key = settings.get("start_hotkey", "f10")
    stop_key = settings.get("stop_hotkey", "f9")

    try:
        ref1 = keyboard.add_hotkey(start_key, start_bot)
        ref2 = keyboard.add_hotkey(stop_key, stop_bot)
        hotkey_refs.extend([ref1, ref2])
        log_message(f"Kısayollar yüklendi: Başlat = {start_key.upper()}, Durdur = {stop_key.upper()}")
    except Exception as e:
        log_message(f"Kısayol hatası: {e}")

def delete_message():
    index = simpledialog.askinteger("Mesaj Sil", "Silmek istediğin mesajın numarasını gir (1'den başlar):")
    if index is None:
        return
    index -= 1
    if 0 <= index < len(messages):
        mesaj = messages.pop(index)
        update_message_frame()
        log_message(f"Mesaj silindi: {mesaj}")
    else:
        messagebox.showwarning("Uyarı", "Geçersiz mesaj numarası.")


def update_message_frame():
    for widget in message_frame.winfo_children():
        widget.destroy()
    for idx, msg in enumerate(messages):
        label = ctk.CTkLabel(message_frame, text=f"{idx+1} - {msg}", anchor="w", font=("Arial", 12))
        label.grid(row=idx, column=0, sticky="w", padx=5, pady=1)


def chat_system():
    load_settings()
    global message_entry, delay_entry, loop_entry
    global start_hotkey_entry, stop_hotkey_entry
    global message_frame, log_text

    ctk.set_appearance_mode(settings["theme"])
    ctk.set_default_color_theme("green")

    app = ctk.CTk()
    app.title("Craftrise Oto Chat Bot")
    app.geometry("620x1024")

    # Mesaj giriş alanı
    ctk.CTkLabel(app, text="Mesaj Ekle:").pack(pady=(15, 0))
    message_entry = ctk.CTkEntry(app, width=400)
    message_entry.pack(pady=10)

    # Butonlar
    btn_frame = ctk.CTkFrame(app)
    btn_frame.pack(pady=10)

    ctk.CTkButton(btn_frame, text="➕ Ekle", command=add_message).grid(row=0, column=0, padx=5)
    ctk.CTkButton(btn_frame, text="💾 Kaydet", command=save_messages).grid(row=0, column=1, padx=5)
    ctk.CTkButton(btn_frame, text="📂 Yükle", command=load_messages).grid(row=0, column=2, padx=5)
    ctk.CTkButton(btn_frame, text="🗑 Sil", command=delete_message).grid(row=0, column=3, padx=5)

    # Mesaj listesi (CTkScrollableFrame + Label)
    ctk.CTkLabel(app, text="Mesaj Listesi:").pack()
    message_frame = ctk.CTkScrollableFrame(app, width=540, height=50)
    message_frame.pack(pady=5)

    # Gecikme ve döngü
    ctk.CTkLabel(app, text="Mesaj Gecikmesi (saniye):").pack()
    delay_entry = ctk.CTkEntry(app, width=100)
    delay_entry.insert(0, str(settings["delay"]))
    delay_entry.pack(pady=3)

    ctk.CTkLabel(app, text="Döngü Sayısı (0 = sınırsız):").pack()
    loop_entry = ctk.CTkEntry(app, width=100)
    loop_entry.insert(0, str(settings["loops"]))
    loop_entry.pack(pady=3)

    # Kısayollar
    ctk.CTkLabel(app, text="Kısayollar (örn: f10, f9, ctrl+alt+k)").pack(pady=(10, 0))
    hotkey_frame = ctk.CTkFrame(app)
    hotkey_frame.pack(pady=5)

    ctk.CTkLabel(hotkey_frame, text="Başlat:").grid(row=0, column=0, padx=5)
    start_hotkey_entry = ctk.CTkEntry(hotkey_frame, width=100)
    start_hotkey_entry.insert(0, settings["start_hotkey"])
    start_hotkey_entry.grid(row=0, column=1, padx=5)

    ctk.CTkLabel(hotkey_frame, text="Durdur:").grid(row=0, column=2, padx=5)
    stop_hotkey_entry = ctk.CTkEntry(hotkey_frame, width=100)
    stop_hotkey_entry.insert(0, settings["stop_hotkey"])
    stop_hotkey_entry.grid(row=0, column=3, padx=5)

    ctk.CTkButton(app, text="💡 Kısayolları Kaydet", command=update_hotkeys).pack(pady=10)

    # Başlat/Durdur butonları
    control_frame = ctk.CTkFrame(app)
    control_frame.pack(pady=10)

    ctk.CTkButton(control_frame, text="▶ Başlat", fg_color="#4caf50", hover_color="#388e3c", command=start_bot).grid(row=0, column=0, padx=10)
    ctk.CTkButton(control_frame, text="■ Durdur", fg_color="#e57373", hover_color="#c62828", command=stop_bot).grid(row=0, column=1, padx=10)

    # Tema değiştir
    ctk.CTkButton(app, text="🌗 Tema Değiştir", command=toggle_theme).pack(pady=(5, 10))

    # Log kutusu
    ctk.CTkLabel(app, text="Log:").pack(pady=(10, 0))
    log_text = ctk.CTkTextbox(app, width=580, height=250, state='disabled')
    log_text.pack(pady=5)

    update_message_frame()
    restart_hotkey_listener()
    app.mainloop()


if __name__ == "__main__":
    hide_console()
    loading_screen()
    show_console()
    key_system()
    time.sleep(1)
    hide_console()
    chat_system()

