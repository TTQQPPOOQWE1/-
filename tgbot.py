import logging
import asyncio
import io
import json
import os
import socket
import threading
import ipaddress
import re
import time # ### НОВОЕ ###
from functools import wraps # ### НОВОЕ ###
from queue import Queue
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes
)
import google.generativeai as genai

# --- Константы ---
TELEGRAM_TOKEN = "7255345172:AAGwgnxZ44cW4J1PWYvNHyaSrSWkRztUJTg"
GEMINI_API_KEY = "AIzaSyDRenay1OM1xvIuC3JoRWnLRoHtew9cd7A"
GEMINI_MODEL = 'gemini-1.5-flash'
USER_DB_FILE = "user_database.json"
THREAD_COUNT = 30
ports = [37777, 8000]
usernames = ['admin']
passwords = ['admin', 'admin123', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890']

# ### НОВОЕ ### - Константы для антиспама
USER_COMMAND_COOLDOWN = 5  # секунд. Задержка между командами для одного юзера
NEW_USER_SAVE_DELAY = 3    # секунд. Задержка при добавлении нового юзера в базу

# --- Логирование ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Глобальные переменные ---
user_states = {}
active_scans = {}
known_user_ids = set() # ### НОВОЕ ### - Кэш пользователей в памяти для быстрой проверки
new_user_queue = asyncio.Queue() # ### НОВОЕ ### - Очередь для регистрации новых пользователей
user_last_command_time = {} # ### НОВОЕ ### - Словарь для отслеживания времени последней команды юзера

# ### НОВОЕ ### - Декоратор для ограничения частоты вызова команд
def rate_limit(limit: int):
    def decorator(func):
        @wraps(func)
        async def wrapped(update: Update, context: ContextTypes.DEFAULT_TYPE, *args, **kwargs):
            user_id = update.effective_user.id
            current_time = time.time()
            last_time = user_last_command_time.get(user_id, 0)

            if current_time - last_time < limit:
                logger.warning(f"Пользователь {user_id} спамит. Команда {func.__name__} отклонена.")
                await update.message.reply_text(f"Пожалуйста, подождите {limit} секунд перед использованием следующей команды.")
                return
            
            user_last_command_time[user_id] = current_time
            return await func(update, context, *args, **kwargs)
        return wrapped
    return decorator

# --- Работа с пользователями ---
def load_user_ids_to_memory():
    """Загружает ID пользователей из файла в кэш (глобальную переменную) при старте."""
    global known_user_ids
    if not os.path.exists(USER_DB_FILE):
        known_user_ids = set()
        return
    try:
        with open(USER_DB_FILE, 'r') as f:
            data = json.load(f)
            known_user_ids = set(data.get("user_ids", []))
            logger.info(f"Загружено {len(known_user_ids)} пользователей в кэш.")
    except (json.JSONDecodeError, FileNotFoundError):
        known_user_ids = set()

# ### ИЗМЕНЕНО ### - Теперь эта функция асинхронная и работает с очередью
async def save_user_id(user_id):
    """Добавляет ID нового пользователя в очередь на сохранение."""
    if user_id not in known_user_ids:
        known_user_ids.add(user_id) # Сразу добавляем в кэш, чтобы избежать повторной постановки в очередь
        await new_user_queue.put(user_id)
        logger.info(f"Новый пользователь {user_id} добавлен в очередь на сохранение.")

# ### НОВОЕ ### - Фоновый процесс для сохранения пользователей из очереди в файл
async def user_database_writer():
    """Бесконечный цикл, который забирает ID из очереди и сохраняет в файл с задержкой."""
    while True:
        try:
            # Ждем, пока в очереди появится новый пользователь
            user_id_to_save = await new_user_queue.get()
            
            # Загружаем текущую базу (на случай, если она изменилась другим способом)
            if os.path.exists(USER_DB_FILE):
                with open(USER_DB_FILE, 'r') as f:
                    try:
                        data = json.load(f)
                        current_ids = set(data.get("user_ids", []))
                    except json.JSONDecodeError:
                        current_ids = set()
            else:
                current_ids = set()
            
            # Добавляем нового пользователя и сохраняем
            current_ids.add(user_id_to_save)
            with open(USER_DB_FILE, 'w') as f:
                json.dump({"user_ids": list(current_ids)}, f)

            logger.info(f"Пользователь {user_id_to_save} сохранен в {USER_DB_FILE}.")
            
            # Отмечаем, что задача из очереди выполнена
            new_user_queue.task_done()

            # Ждем перед обработкой следующего
            await asyncio.sleep(NEW_USER_SAVE_DELAY)

        except Exception as e:
            logger.error(f"Ошибка в фоновом процессе сохранения пользователей: {e}")
            await asyncio.sleep(5) # Ждем 5 секунд в случае ошибки

# --- Валидация формата логов для /xml ---
def validate_log_format(content: str) -> bool:
    pattern1 = re.compile(r'^\S+:\S+\s+\d{1,3}(\.\d{1,3}){3}:\d+$')
    pattern2 = re.compile(r'^\d{1,3}(\.\d{1,3}){3}\s*=>\s*\S+:\S+$')
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        if not (pattern1.match(line) or pattern2.match(line)):
            return False
    return True

# --- Команды ---
# ### ИЗМЕНЕНО ### - Добавлен декоратор @rate_limit
@rate_limit(USER_COMMAND_COOLDOWN)
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user = update.effective_user
    await save_user_id(user.id) # ### ИЗМЕНЕНО ### - Вызов асинхронной версии
    await update.message.reply_html(
        f"Привет, {user.mention_html()}! Я многофункциональный бот.\n"
        "Доступные команды:\n"
        "/v6 - Очистить файл от IPv6 адресов\n"
        "/xml - Сгенерировать XML из логов\n"
        "/scanner - Сканировать IP диапазоны\n"
        "/stop - Остановить сканирование"
    )

@rate_limit(USER_COMMAND_COOLDOWN)
async def v6_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_states[chat_id] = 'waiting_for_v6_file'
    await update.message.reply_text("Прикрепите .txt файл для удаления строк с IPv6 (содержащих ':').")

@rate_limit(USER_COMMAND_COOLDOWN)
async def xml_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    user_states[chat_id] = 'waiting_for_xml_file'
    await update.message.reply_text("Прикрепите .txt файл с логами в формате `юзер:пароль айпи:порт` или `айпи => юзер:пароль` для XML.")

@rate_limit(USER_COMMAND_COOLDOWN)
async def scanner_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    user_states[chat_id] = 'waiting_for_ranges_file'
    await update.message.reply_text("Пришлите файл `ranges.txt` с диапазонами IP для сканирования.")

@rate_limit(USER_COMMAND_COOLDOWN)
async def stop_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    if user_id in active_scans:
        active_scans[user_id]["stop"].set()
        # Не удаляем сразу, дадим потоку завершиться и почистить за собой
        await update.message.reply_text("⛔️ Сканирование останавливается...")
    else:
        await update.message.reply_text("❌ Нет активного сканирования.")

# --- Обработка файлов ---
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    chat_id = update.effective_chat.id
    if chat_id not in user_states:
        return
    
    # ### НОВОЕ ### - Применяем rate-limit и к отправке файлов
    user_id = update.effective_user.id
    current_time = time.time()
    last_time = user_last_command_time.get(user_id, 0)
    if current_time - last_time < USER_COMMAND_COOLDOWN:
        logger.warning(f"Пользователь {user_id} спамит файлами. Отклонено.")
        await update.message.reply_text(f"Пожалуйста, подождите {USER_COMMAND_COOLDOWN} секунд перед отправкой следующего файла.")
        return
    user_last_command_time[user_id] = current_time

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
        
        if chat_id in active_scans:
            await update.message.reply_text("У вас уже запущено сканирование. Остановите его командой /stop перед запуском нового.")
            return

        stop_event = threading.Event()
        scanner = Scanner(ips, update.effective_user.username, chat_id, context, stop_event)
        active_scans[chat_id] = {"scanner": scanner, "stop": stop_event}

        await update.message.reply_text(f"Сканирование началось. Всего IP для проверки: {len(ips)}. Ожидайте...")
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
    # ... (логика без изменений)
    lines = content.splitlines()
    ipv4_lines = [line for line in lines if ':' not in line]
    if not ipv4_lines:
        await update.message.reply_text("В файле не найдено строк без символа ':' (IPv4).")
        return
    output_file = io.BytesIO("\n".join(ipv4_lines).encode('utf-8'))
    output_file.name = 'ipv4_only.txt'
    await update.message.reply_document(document=output_file, caption="Готово! Удалены IPv6.")

async def process_xml_file(update: Update, content: str):
    # ... (логика без изменений)
    if not validate_log_format(content):
        await update.message.reply_text(
            "Ошибка: неверный формат файла. Ожидается формат:\n"
            "`юзер:пароль айпи:порт` или `айпи => юзер:пароль` в каждой строке.",
            parse_mode='Markdown'
        )
        return
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        prompt = f"""
Преобразуй строки логов в XML. Формат строк: юзер:пароль айпи:порт
<Organization><Department name=\"root\">...Devices...</Department></Organization>
---
{content}
---
"""
        response = await model.generate_content_async(prompt)
        generated_xml = response.text.strip().strip('```xml').strip('```')
        output_file = io.BytesIO(generated_xml.encode('utf-8'))
        output_file.name = 'devices.xml'
        await update.message.reply_document(document=output_file, caption="XML-файл успешно сгенерирован.")
    except Exception as e:
        logger.error(f"Ошибка при работе с Gemini API: {e}")
        await update.message.reply_text(f"Произошла ошибка при генерации XML. {e}")

# --- Сканер ---
def expand_range(line):
    # ... (логика без изменений)
    if '-' in line:
        start_ip, end_ip = line.split('-')
        return [str(ip) for ip in ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip.strip()), ipaddress.IPv4Address(end_ip.strip()))]
    return [line.strip()]

def load_ips_from_ranges(user_id):
    # ... (логика без изменений)
    filepath = f'ranges/{user_id}.txt'
    ips = []
    if not os.path.exists(filepath):
        return ips
    with open(filepath, 'r') as f:
        for line in f:
            try:
                for net in expand_range(line.strip()):
                    for ip in ipaddress.ip_network(net, strict=False).hosts():
                        ips.append(str(ip))
            except: continue
    return ips

def check_port(ip, port):
    # ... (логика без изменений)
    try:
        with socket.create_connection((ip, port), timeout=1.5):
            return True
    except:
        return False

def try_login(ip, port):
    # ... (логика без изменений)
    for username in usernames:
        for password in passwords:
            if password == 'admin': # Это заглушка, в реальности тут должен быть настоящий логин
                return True, username, password
    return False, None, None

class Scanner:
    # ... (логика класса Scanner без изменений)
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
            
            if self.stop_event.is_set(): # Дополнительная проверка
                break

            for port in ports:
                if check_port(ip, port):
                    with self.lock: self.open_count += 1
                    ok, u, p = try_login(ip, port)
                    if ok:
                        with self.lock: self.success_count += 1
                        # Используем run_coroutine_threadsafe для вызова async функции из потока
                        asyncio.run_coroutine_threadsafe(
                            self.context.bot.send_message(chat_id=self.user_id, text=f"Камера найдена ✅\n{ip} => {u}:{p}"),
                            self.context.application.loop
                        )
                        break
            self.ip_queue.task_done()

    def run(self):
        threads = []
        for _ in range(THREAD_COUNT):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)
        
        self.ip_queue.join()
        
        # ### ИЗМЕНЕНО ### - Более корректное завершение и отчет
        self.stop_event.set() # Убеждаемся, что флаг установлен
        for t in threads:
            t.join() # Ждем завершения всех потоков

        # Отправляем итоговое сообщение
        final_message = f"✅ Сканирование завершено. Найдено совпадений: {self.success_count}."
        asyncio.run_coroutine_threadsafe(
            self.context.bot.send_message(chat_id=self.user_id, text=final_message),
            self.context.application.loop
        )

        # Удаляем скан из активных
        if self.user_id in active_scans:
            del active_scans[self.user_id]


# --- Init ---
# ### ИЗМЕНЕНО ### - Запускаем фоновые задачи при инициализации
async def post_init(application: Application) -> None:
    load_user_ids_to_memory()
    # Запускаем фоновый процесс для сохранения новых пользователей
    asyncio.create_task(user_database_writer())
    logger.info("Бот инициализирован. Фоновый процесс сохранения пользователей запущен.")

def main():
    # ### ИЗМЕНЕНО ### - Убран `post_init` из builder, т.к. он теперь `async`
    application = Application.builder().token(TELEGRAM_TOKEN).build()
    
    # ### ИЗМЕНЕНО ### - Добавляем `post_init` отдельно
    application.post_init = post_init

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("v6", v6_command))
    application.add_handler(CommandHandler("xml", xml_command))
    application.add_handler(CommandHandler("scanner", scanner_command))
    application.add_handler(CommandHandler("stop", stop_command))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    
    application.run_polling()

if __name__ == '__main__':
    main()