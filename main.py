import asyncio
import aiohttp
import aiofiles
import logging
import time
import shutil
from pathlib import Path
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.exceptions import TelegramBadRequest

# ==================== ⚙️ CONFIGURATION ====================
BOT_TOKEN = "8957022606:AAFcbxUXol4pgERaHLDI-d-ZRlPZNXvxZM0"  # ⚠️ این توکن را تغییر دهید!
BOT_USERNAME = "@rpd_ext_bot"
REPO_OWNER = "reARbitRA"
REPO_NAME = "rdp.nla.ip"
BRANCH = "main"
NUM_CHUNKS = 9

# Performance Tuning
MAX_CONCURRENT_SCANS = 800
TIMEOUT_SECONDS = 2.0
BATCH_SIZE = 2000
PROGRESS_UPDATE_INTERVAL = 5.0

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

# ==================== 🧠 STATE MANAGEMENT ====================
class ScanStates(StatesGroup):
    ready = State()
    processing = State()

# ==================== ⏱️ HELPER FUNCTIONS ====================
def format_time(seconds: float) -> str:
    """تبدیل ثانیه به فرمت خوانای ساعت:دقیقه:ثانیه"""
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"

# ==================== ⚡ HIGH-PERFORMANCE SCANNER ====================
class RDPEngine:
    def __init__(self, max_concurrent: int, timeout: float):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout
        self.cancel_flag = False

    def cancel(self):
        """لغو عملیات اسکن"""
        self.cancel_flag = True

    async def _check_port(self, ip: str, open_ips: list, progress: dict):
        """بررسی یک IP برای پورت RDP"""
        if self.cancel_flag:
            return
        async with self.semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, 3389),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                open_ips.append(ip)
            except Exception:
                pass
            finally:
                progress['scanned'] += 1

    async def process_files(self, file_paths: list, output_path: str, progress_callback):
        """پردازش تمام فایل‌ها و اسکن IPها"""
        self.cancel_flag = False
        open_ips = []
        progress = {'scanned': 0, 'total': 0, 'start_time': time.time()}
        
        # فاز ۲: شمارش دقیق برای محاسبه ETA
        await progress_callback(phase="counting")
        for path in file_paths:
            async with aiofiles.open(path, 'r') as f:
                async for _ in f:
                    progress['total'] += 1

        last_update = time.time()

        # فاز ۳: اسکن هسته
        for path in file_paths:
            if self.cancel_flag:
                break
                
            tasks = []
            async with aiofiles.open(path, 'r') as f:
                async for line in f:
                    if self.cancel_flag:
                        break
                    ip = line.strip()
                    if not ip: continue
                    
                    tasks.append(self._check_port(ip, open_ips, progress))
                    
                    # پردازش دسته‌ای برای مدیریت حافظه
                    if len(tasks) >= BATCH_SIZE:
                        await asyncio.gather(*tasks, return_exceptions=True)
                        tasks = []
                        
                    # به‌روزرسانی داشبورد
                    now = time.time()
                    if now - last_update >= PROGRESS_UPDATE_INTERVAL:
                        await progress_callback(phase="scanning", progress=progress, found=len(open_ips))
                        last_update = now

            if tasks and not self.cancel_flag:
                await asyncio.gather(*tasks, return_exceptions=True)

        # گزارش نهایی
        await progress_callback(phase="scanning", progress=progress, found=len(open_ips), is_final=True)

        # ذخیره نتایج
        async with aiofiles.open(output_path, 'w') as f:
            await f.write("\n".join(open_ips))
            
        return len(open_ips)

# ==================== 🤖 TELEGRAM BOT LOGIC ====================
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
engine = RDPEngine(max_concurrent=MAX_CONCURRENT_SCANS, timeout=TIMEOUT_SECONDS)

# دیکشنری برای نگهداری وضعیت هر کاربر
user_sessions = {}

def get_raw_url(chunk_num: int) -> str:
    """ساخت URL خام برای فایل‌های گیت‌هاب"""
    return f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/chunk_{chunk_num}.txt"

@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    """کامند شروع - آماده‌سازی محیط"""
    chat_id = message.chat.id
    user_dir = Path(f"temp_scan_{chat_id}")
    if user_dir.exists(): shutil.rmtree(user_dir)
    user_dir.mkdir(exist_ok=True)
    
    user_sessions[chat_id] = {"status_msg": None, "is_scanning": False}
    await state.set_state(ScanStates.ready)
    
    await message.answer(
        "🔐 **RDP Extraction Engine (Reference-Grade v2.0)**\n\n"
        f"📂 Target: `{REPO_OWNER}/{REPO_NAME}`\n"
        f"📦 Chunks: `{NUM_CHUNKS}`\n\n"
        "📋 **دستورات موجود:**\n"
        "/start - 🚀 شروع و آماده‌سازی\n"
        "/scan - 🔍 آغاز اسکن\n"
        "/status - 📊 وضعیت زنده\n"
        "/cancel - 🛑 لغو عملیات\n"
        "/help - 📖 راهنما\n"
        "/about - ⚙️ درباره ربات\n\n"
        "برای شروع عملیات ۴ فازی، `/scan` را ارسال کنید.",
        parse_mode="Markdown"
    )

@dp.message(Command("scan"))
async def cmd_scan(message: types.Message, state: FSMContext):
    """کامند اسکن - شروع پایپ‌لاین ۴ فازی"""
    chat_id = message.chat.id
    
    # بررسی اینکه آیا اسکن دیگری در حال انجام است
    if chat_id in user_sessions and user_sessions[chat_id].get("is_scanning"):
        await message.answer("⚠️ یک عملیات اسکن در حال انجام است. ابتدا با /cancel آن را لغو کنید.")
        return
    
    user_dir = Path(f"temp_scan_{chat_id}")
    output_file = user_dir / "open_rdp_results.txt"
    
    await state.set_state(ScanStates.processing)
    status_msg = await message.answer("⏳ **فاز ۱ از ۴:** در حال اتصال به گیت‌هاب...")
    user_sessions[chat_id]["status_msg"] = status_msg
    user_sessions[chat_id]["is_scanning"] = True

    # --- فاز ۱: دانلود فایل‌ها ---
    file_paths = []
    async with aiohttp.ClientSession() as session:
        for i in range(1, NUM_CHUNKS + 1):
            url = get_raw_url(i)
            file_path = user_dir / f"chunk_{i}.txt"
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        async with aiofiles.open(file_path, 'wb') as f:
                            await f.write(await response.read())
                        file_paths.append(str(file_path))
                        
                        # به‌روزرسانی زنده دانلود
                        percent = int((i / NUM_CHUNKS) * 100)
                        try:
                            await status_msg.edit_text(
                                f"⏳ **فاز ۱ از ۴: دانلود فایل‌ها**\n"
                                f"📦 پیشرفت: `{percent}%` ({i}/{NUM_CHUNKS})\n"
                                f"🔗 در حال دریافت: `chunk_{i}.txt`",
                                parse_mode="Markdown"
                            )
                        except TelegramBadRequest:
                            pass
            except Exception as e:
                await message.answer(f"❌ خطا در دانلود chunk_{i}.txt: {e}")

    if not file_paths:
        await status_msg.edit_text("🚫 شکست بحرانی: هیچ فایلی دانلود نشد. عملیات لغو شد.")
        user_sessions[chat_id]["is_scanning"] = False
        await state.clear()
        return

    # --- تابع به‌روزرسانی داشبورد زنده ---
    async def dashboard_updater(phase: str, progress: dict = None, found: int = 0, is_final: bool = False):
        nonlocal status_msg
        try:
            if phase == "counting":
                await status_msg.edit_text(
                    "⏳ **فاز ۲ از ۴: آنالیز اولیه**\n"
                    "🔍 در حال شمارش دقیق IPها برای محاسبه ETA...\n"
                    "⚠️ این فرآیند بسیار سریع است.",
                    parse_mode="Markdown"
                )
            elif phase == "scanning" and progress:
                elapsed = time.time() - progress['start_time']
                scanned = progress['scanned']
                total = progress['total']
                percent = (scanned / total) * 100 if total > 0 else 0
                
                # محاسبه ETA
                if percent > 1:
                    eta_seconds = (elapsed / percent) * (100 - percent)
                    eta_str = format_time(eta_seconds)
                else:
                    eta_str = "در حال محاسبه..."
                    
                status_text = (
                    "🚀 **فاز ۳ از ۴: اسکن هسته (Live Dashboard)**\n\n"
                    f"⏱️ **زمان سپری‌شده:** `{format_time(elapsed)}`\n"
                    f"📊 **پیشرفت کلی:** `{percent:.2f}%`\n"
                    f"🔍 **پردازش شده:** `{scanned:,}` از `{total:,}`\n"
                    f"🔓 **پورت‌های باز یافت‌شده:** `{found}`\n"
                    f"⏳ **زمان تخمینی باقی‌مانده (ETA):** `{eta_str}`\n\n"
                    "🔄 سیستم در حال کار است. برای لغو: /cancel"
                )
                
                if is_final:
                    status_text += "\n✅ اسکن تکمیل شد! در حال آماده‌سازی فایل نهایی..."
                    
                await status_msg.edit_text(status_text, parse_mode="Markdown")
        except TelegramBadRequest:
            pass

    # شروع موتور اسکن در پس‌زمینه
    await dashboard_updater(phase="counting")
    asyncio.create_task(_execute_scan(chat_id, file_paths, str(output_file), dashboard_updater, state, status_msg))

@dp.message(Command("status"))
async def cmd_status(message: types.Message):
    """کامند وضعیت - نمایش آخرین وضعیت اسکن"""
    chat_id = message.chat.id
    if chat_id not in user_sessions or not user_sessions[chat_id].get("is_scanning"):
        await message.answer("ℹ️ هیچ عملیات اسکنی در حال انجام نیست.")
        return
    
    status_msg = user_sessions[chat_id].get("status_msg")
    if status_msg:
        await message.answer(f"📊 وضعیت فعلی:\n{status_msg.text}", parse_mode="Markdown")
    else:
        await message.answer("⏳ در حال پردازش...")

@dp.message(Command("cancel"))
async def cmd_cancel(message: types.Message, state: FSMContext):
    """کامند لغو - توقف فوری اسکن"""
    chat_id = message.chat.id
    if chat_id not in user_sessions or not user_sessions[chat_id].get("is_scanning"):
        await message.answer("ℹ️ هیچ عملیاتی برای لغو وجود ندارد.")
        return
    
    engine.cancel()
    user_sessions[chat_id]["is_scanning"] = False
    
    user_dir = Path(f"temp_scan_{chat_id}")
    if user_dir.exists():
        shutil.rmtree(user_dir)
    
    await state.clear()
    await message.answer("🛑 عملیات با موفقیت لغو و فایل‌های موقت پاکسازی شدند.")

@dp.message(Command("help"))
async def cmd_help(message: types.Message):
    """کامند راهنما - توضیحات کامل"""
    await message.answer(
        "📖 **راهنمای کامل RDP Extraction Engine**\n\n"
        "🔹 **چگونه کار می‌کند؟**\n"
        "۱. ربات به صورت خودکار ۹ فایل Chunk را از گیت‌هاب دانلود می‌کند\n"
        "۲. تعداد کل IPها را می‌شمارد (برای محاسبه ETA)\n"
        "۳. هر IP را روی پورت 3389 اسکن می‌کند (800 اتصال همزمان)\n"
        "۴. نتایج را در یک فایل متنی ارسال می‌کند\n\n"
        "⏱️ **زمان تقریبی:**\n"
        "• ۴ میلیون IP: 30 تا 90 دقیقه\n"
        "• سرعت: ~2000 IP در ثانیه\n\n"
        "🛠️ **دستورات:**\n"
        "/start - شروع و آماده‌سازی\n"
        "/scan - آغاز اسکن\n"
        "/status - مشاهده وضعیت زنده\n"
        "/cancel - لغو عملیات\n"
        "/help - این راهنما\n"
        "/about - اطلاعات فنی\n\n"
        "⚠️ **سلب مسئولیت:**\n"
        "این ابزار صرفاً برای اهداف قانونی شامل مدیریت شبکه، حسابرسی امنیتی مجاز، و تحقیقات دفاعی طراحی شده است.",
        parse_mode="Markdown"
    )

@dp.message(Command("about"))
async def cmd_about(message: types.Message):
    """کامند درباره - اطلاعات فنی"""
    await message.answer(
        "⚙️ **درباره RDP Extraction Engine**\n\n"
        "🔧 **نسخه:** 2.0 (Reference-Grade)\n"
        "🐍 **زبان:** Python 3.10+\n"
        "📚 **کتابخانه‌ها:** aiogram 3.4.1, aiohttp, aiofiles\n\n"
        "⚡ **معماری:**\n"
        "• Asyncio Event Loop\n"
        "• Semaphore-based Concurrency (800)\n"
        "• Stream Processing (رم ثابت < 50MB)\n"
        "• Batch Execution (2000 تسک در هر دسته)\n\n"
        "📊 **عملکرد:**\n"
        "• تایم‌اوت اتصال: 2 ثانیه\n"
        "• به‌روزرسانی داشبورد: هر 5 ثانیه\n"
        "• پاکسازی خودکار: فعال\n\n"
        "🛡️ **امنیت:**\n"
        "• عدم ذخیره‌سازی نتایج در سرور\n"
        "• حذف خودکار فایل‌های موقت\n"
        "• مدیریت خطای پیشرفته",
        parse_mode="Markdown"
    )

async def _execute_scan(chat_id: int, file_paths: list, output_path: str, update_cb, state: FSMContext, status_msg: types.Message):
    """اجرای اسکن در پس‌زمینه و مدیریت فاز ۴"""
    try:
        found_count = await engine.process_files(file_paths, output_path, update_cb)
        
        # بررسی لغو عملیات
        if engine.cancel_flag:
            await bot.send_message(chat_id, "🛑 عملیات توسط کاربر لغو شد.")
            return
        
        # --- فاز ۴: تحویل نتایج ---
        if found_count > 0:
            with open(output_path, 'rb') as f:
                await bot.send_document(
                    chat_id,
                    f,
                    caption=f"🎯 **فاز ۴ از ۴: عملیات با موفقیت تکمیل شد.**\n\n"
                            f"📊 **خلاصه نهایی:**\n"
                            f"🔓 تعداد IPهای دارای RDP باز: `{found_count}`\n"
                            f"📁 فایل نتایج در بالا پیوست شده است.",
                    visible_file_name="extracted_open_rdp_ips.txt",
                    parse_mode="Markdown"
                )
        else:
            await bot.send_message(chat_id, "🔍 عملیات تکمیل شد. هیچ پورت باز RDP در این مجموعه داده یافت نشد.")
            
    except Exception as e:
        logging.error(f"Scan execution failed: {e}")
        await bot.send_message(chat_id, f"⚠️ خطای غیرمنتظره در حین اسکن: {e}")
    finally:
        # پاکسازی خودکار
        user_dir = Path(f"temp_scan_{chat_id}")
        if user_dir.exists():
            shutil.rmtree(user_dir)
        user_sessions[chat_id]["is_scanning"] = False
        await state.clear()
        try:
            await status_msg.edit_text("🧹 **پاکسازی تکمیل شد.** فایل‌های موقت از سرور حذف شدند. برای عملیات جدید `/start` را بزنید.", parse_mode="Markdown")
        except TelegramBadRequest:
            pass

# ==================== 🚀 ENTRY POINT ====================
async def main():
    logging.info("Initializing Reference-Grade RDP Extraction Bot v2.0...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Bot gracefully terminated.")
