import logging
import asyncio
import io
import json
import os
import socket
import threading
import ipaddress
from queue import Queue
from telegram import Update, InputFile
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes
)
import google.generativeai as genai

# --- Константы ---
TELEGRAM_TOKEN = "8106025359:AAG5wiA0LGF6rzaFkjYTil0-xXiWhJlPULk"
GEMINI_API_KEY = "AIzaSyDRenay1OM1xvIuC3JoRWnLRoHtew9cd7A"
GEMINI_MODEL = 'gemini-2.0-flash'
USER_DB_FILE = "user_database.json"
THREAD_COUNT = 30
ports = [37777, 8000]
usernames = ['admin']
passwords = ['admin', 'admin123', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890']

# --- Логирование ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Глобальные переменные ---
user_states = {}
active_scans = {}

# --- Работа с пользователями ---
def load_user_ids():
    if not os.path.exists(USER_DB_FILE):
        return set()
    try:
        with open(USER_DB_FILE, 'r') as f:
            data = json.load(f)
            return set(data.get("user_ids", []))
    except (json.JSONDecodeError, FileNotFoundError):
        return set()

def save_user_id(user_id):
    user_ids = load_user_ids()
    if user_id not in user_ids:
        user_ids.add(user_id)
        with open(USER_DB_FILE, 'w') as f:
            json.dump({"user_ids": list(user_ids)}, f)
        logger.info(f"Новый пользователь {user_id} добавлен в базу.")

# --- Команды ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    save_user_id(user.id)
    await update.message.reply_html(
        f"Привет, {user.mention_html()}! Я многофункциональный бот.\n"
        "Доступные команды:\n"
        "/v6 - Очистить файл от IPv6 адресов\n"
        "/xml - Сгенерировать XML из логов\n"
        "/scanner - Сканировать IP диапазоны\n"
        "/stop - Остановить сканирование"
    )

async def v6_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_states[chat_id] = 'waiting_for_v6_file'
    await update.message.reply_text("Прикрепите .txt файл для удаления строк с IPv6 (содержащих ':').")

async def xml_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_states[chat_id] = 'waiting_for_xml_file'
    await update.message.reply_text("Прикрепите .txt файл с логами в формате `юзер:пароль айпи:порт` или `айпи => юзер:пароль` для XML.")

async def scanner_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    user_states[chat_id] = 'waiting_for_ranges_file'
    await update.message.reply_text("Пришлите файл `ranges.txt` с диапазонами IP для сканирования.")

async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in active_scans:
        active_scans[user_id]["stop"].set()
        del active_scans[user_id]
        await update.message.reply_text("⛔️ Сканирование остановлено.")
    else:
        await update.message.reply_text("❌ Нет активного сканирования.")

# --- Обработка файлов ---
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    if chat_id not in user_states:
        return

    state = user_states[chat_id]
    document = update.message.document

    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("Ошибка: Пожалуйста, отправьте файл с расширением .txt")
        return

    file = await document.get_file()

    if state == 'waiting_for_ranges_file':
        # Убираем проверку имени файла
        os.makedirs('ranges', exist_ok=True)
        filepath = f"ranges/{chat_id}.txt"
        await file.download_to_drive(filepath)

        ips = load_ips_from_ranges(chat_id)
        if not ips:
            await update.message.reply_text("Файл пуст или невалидный.")
            return

        stop_event = threading.Event()
        scanner = Scanner(ips, update.effective_user.username, chat_id, context, stop_event)
        active_scans[chat_id] = {"scanner": scanner, "stop": stop_event}

        await update.message.reply_text("Ожидайте, сканирование началось...")
        threading.Thread(target=scanner.run).start()
        del user_states[chat_id]
        return


    state = user_states[chat_id]
    document = update.message.document

    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("Ошибка: Пожалуйста, отправьте файл с расширением .txt")
        return

    file = await document.get_file()

    if state == 'waiting_for_ranges_file':
        if document.file_name != "ranges.txt":
            await update.message.reply_text("Пожалуйста, переименуйте файл в ranges.txt и отправьте снова.")
            return

        os.makedirs('ranges', exist_ok=True)
        filepath = f"ranges/{chat_id}.txt"
        await file.download_to_drive(filepath)

        ips = load_ips_from_ranges(chat_id)
        if not ips:
            await update.message.reply_text("Файл пуст или невалидный.")
            return

        stop_event = threading.Event()
        scanner = Scanner(ips, update.effective_user.username, chat_id, context, stop_event)
        active_scans[chat_id] = {"scanner": scanner, "stop": stop_event}

        await update.message.reply_text("Ожидайте, сканирование началось...")
        threading.Thread(target=scanner.run).start()
        del user_states[chat_id]
        return

    file_content_bytes = await file.download_as_bytearray()
    file_content_str = file_content_bytes.decode('utf-8', errors='ignore')

    if state == 'waiting_for_v6_file':
        await process_v6_file(update, file_content_str)
    elif state == 'waiting_for_xml_file':
        await process_xml_file(update, file_content_str)

    del user_states[chat_id]

async def process_v6_file(update: Update, content: str):
    lines = content.splitlines()
    ipv4_lines = [line for line in lines if ':' not in line]
    if not ipv4_lines:
        await update.message.reply_text("В файле не найдено строк без символа ':' (IPv4).")
        return
    output_file = io.BytesIO("\n".join(ipv4_lines).encode('utf-8'))
    output_file.name = 'ipv4_only.txt'
    await update.message.reply_document(document=output_file, caption="Готово! Удалены IPv6.")

async def process_xml_file(update: Update, content: str):
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        generation_config = genai.types.GenerationConfig(max_output_tokens=600000)

        prompt = f"""
Преобразуй следующие строки логов в XML-формат.
Каждая строка имеет вид "юзернейм:пароль айпи:порт".
Игнорируй любые строки, которые не соответствуют этому формату.
Не добавляй никаких объяснений или форматирования, просто верни готовый XML.

Структура XML:
<Organization>
    <Department name="root">
        <!-- Тут теги Device -->
    </Department>
</Organization>

Пример:
<Device title="185.156.152.19" ip="185.156.152.19" port="37777" user="admin" password="admin"/>

Вот данные:
---
{content}
---
"""
        response = await model.generate_content_async(prompt, generation_config=generation_config)
        generated_xml = response.text.strip().strip('```xml').strip('```')

        if not generated_xml.endswith('</Organization>'):
            logger.warning("Ответ обрезан, возможно превышен лимит.")

        output_file = io.BytesIO(generated_xml.encode('utf-8'))
        output_file.name = 'devices.xml'
        await update.message.reply_document(document=output_file, caption="XML-файл успешно сгенерирован.")
    except Exception as e:
        logger.error(f"Ошибка при работе с Gemini API: {e}")
        await update.message.reply_text(f"Произошла ошибка при генерации XML. {e}")

# --- Сканер ---
def expand_range(line):
    if '-' in line:
        try:
            start_ip, end_ip = line.split('-')
            start = int(ipaddress.IPv4Address(start_ip.strip()))
            end = int(ipaddress.IPv4Address(end_ip.strip()))
            return [str(ipaddress.IPv4Address(ip)) for ip in range(start, end + 1)]
        except Exception as e:
            logger.warning(f"Ошибка в диапазоне '{line}': {e}")
            return []
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
            if not line or line.startswith("#"):
                continue
            ips.extend(expand_range(line))
    return ips

def check_port(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1.5):
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
        self.total = len(ips)
        self.checked = 0
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

                        # Вывод в консоль найденной камеры с портом, IP, юзером, паролем
                        print(f"Найдена камера: {ip}:{port} => {u}:{p}")

                        # Отправляем пользователю сообщение с портом, айпи, юзером и паролем
                        asyncio.run(self.context.bot.send_message(
                            chat_id=self.user_id,
                            text=f"✅ Камера найдена:\nIP: {ip}\nПорт: {port}\nПользователь: {u}\nПароль: {p}",
                            parse_mode="Markdown"
                        ))
                        break  # Если камера найдена на порту, не проверяем остальные порты

            with self.lock:
                self.checked += 1
                if self.checked % 20 == 0:
                    # Выводим прогресс в консоль
                    print(f"🔄 Прогресс: {self.checked}/{self.total} | Открытых портов: {self.open_count} | Успешных логинов: {self.success_count}")

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

import asyncio

async def send_finish_message(bot, user_id, total, open_count, success_count):
    await bot.send_message(
        chat_id=user_id,
        text=f"🏁 Сканирование завершено!\nIP всего: {total}\nОткрытых портов: {open_count}\nКамер найдено: {success_count}"
    )

def run(self):
    # Запускаем потоки
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

    # Отправка финального сообщения
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    asyncio.run_coroutine_threadsafe(
        send_finish_message(self.context.bot, self.user_id, self.total, self.open_count, self.success_count),
        loop
    )


# --- Init ---
async def post_init(application: Application) -> None:
    logger.info("Бот инициализирован.")

def main():
    application = Application.builder().token(TELEGRAM_TOKEN).post_init(post_init).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("v6", v6_command))
    application.add_handler(CommandHandler("xml", xml_command))
    application.add_handler(CommandHandler("scanner", scanner_command))
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    application.run_polling()

if __name__ == '__main__':
    main()
