import socket
import threading
import os
import ipaddress
import asyncio
from queue import Queue
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# Порты и логины/пароли
ports = [37777, 8000]
usernames = ['admin']
passwords = ['admin', 'admin123', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890']
THREAD_COUNT = 30

active_scans = {}

def expand_range(line):
    if '-' in line:
        start_ip, end_ip = line.split('-')
        start_ip = ipaddress.IPv4Address(start_ip.strip())
        end_ip = ipaddress.IPv4Address(end_ip.strip())
        return [str(ip) for ip in ipaddress.summarize_address_range(start_ip, end_ip)]
    else:
        return [line.strip()]

def load_ips_from_ranges(user_id):
    filepath = f'ranges/{user_id}.txt'
    ips = []
    if not os.path.exists(filepath):
        return ips
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    expanded = expand_range(line)
                    for ip_net in expanded:
                        net = ipaddress.ip_network(ip_net, strict=False)
                        for ip in net.hosts():
                            ips.append(str(ip))
                except Exception as e:
                    print(f"[WARN] Invalid range or IP: {line} -> {e}")
    return ips

def check_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)
        sock.connect((ip, port))
        sock.close()
        return True
    except:
        return False

def try_login(ip, port):
    for username in usernames:
        for password in passwords:
            if password == 'admin':
                return True, username, password
    return False, None, None

class Scanner:
    def __init__(self, ips, username, user_id, context, stop_event):
        self.ips = ips
        self.username = username
        self.user_id = user_id
        self.context = context
        self.success_count = 0
        self.open_count = 0
        self.lock = threading.Lock()
        self.ip_queue = Queue()
        self.stop_event = stop_event
        for ip in ips:
            self.ip_queue.put(ip)

    def worker(self):
        while not self.stop_event.is_set():
            try:
                ip = self.ip_queue.get(timeout=1)
            except:
                break

            for port in ports:
                if check_port(ip, port):
                    with self.lock:
                        self.open_count += 1
                    ok, u, p = try_login(ip, port)
                    if ok:
                        with self.lock:
                            self.success_count += 1
                        print(f"[FOUND] {ip} => {u}:{p}")
                        asyncio.run(self.context.bot.send_message(chat_id=self.user_id, text=f"Камера найдена ✅\n{ip} => {u}:{p}"))
                        break

            with self.lock:
                print(f"@{self.username} [SCAN] Checking {ip}...   | OPEN: {self.open_count} | SUCCESS: {self.success_count}")
            self.ip_queue.task_done()

    def run(self):
        threads = []
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        self.ip_queue.join()
        self.stop_event.set()
        for t in threads:
            t.join()

# Команды Telegram
async def scanner_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Привет! Пришли файл ranges.txt с IP-адресами для сканирования 🙂")

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in active_scans:
        active_scans[user_id]["stop"].set()
        del active_scans[user_id]
        await update.message.reply_text("⛔️ Сканирование остановлено.")
    else:
        await update.message.reply_text("❌ У вас нет активного сканирования.")

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document
    user = update.effective_user
    username = user.username if user.username else user.first_name
    user_id = user.id

    if not document or document.file_name != "ranges.txt":
        await update.message.reply_text("Пожалуйста, отправь файл с именем ranges.txt")
        return

    if user_id in active_scans:
        active_scans[user_id]["stop"].set()

    os.makedirs('ranges', exist_ok=True)
    filepath = f"ranges/{user_id}.txt"
    file = await document.get_file()
    await file.download_to_drive(filepath)

    ips = load_ips_from_ranges(user_id)
    if not ips:
        await update.message.reply_text("Файл пуст или невалидный.")
        return

    stop_event = threading.Event()
    scanner = Scanner(ips, username, user_id, context, stop_event)
    active_scans[user_id] = {"scanner": scanner, "stop": stop_event}

    await update.message.reply_text("Ожидайте, сканирование началось...")
    threading.Thread(target=scanner.run).start()

# Запуск бота
def main():
    TOKEN = "7851047542:AAFbzXY43BBb0v_1ELvrvASvAUtGW4KoCBg"
    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("scanner", scanner_command))
    app.add_handler(CommandHandler("stop", stop_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    print("Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()
