import asyncio
import aiohttp
import aiofiles
import logging
import os
import shutil
from pathlib import Path
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

# ==================== ⚙️ CONFIGURATION ====================
BOT_TOKEN = "8957022606:AAFcbxUXol4pgERaHLDI-d-ZRlPZNXvxZM0"  # ⚠️ Rotate this if exposed publicly!
REPO_OWNER = "reARbitRA"
REPO_NAME = "rdp.nla.ip"
BRANCH = "main"
NUM_CHUNKS = 9

# Performance Tuning
MAX_CONCURRENT_SCANS = 800  # Adjust based on your network bandwidth and OS limits
TIMEOUT_SECONDS = 2.0       # Strict timeout to prevent hanging on unresponsive IPs
BATCH_SIZE = 2000           # Process in batches to keep RAM usage near zero

logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

# ==================== 🧠 STATE MANAGEMENT ====================
class ScanStates(StatesGroup):
    ready = State()
    scanning = State()

# ==================== ⚡ HIGH-PERFORMANCE SCANNER ====================
class RDPEngine:
    def __init__(self, max_concurrent: int, timeout: float):
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.timeout = timeout

    async def _check_port(self, ip: str, open_ips: list, progress: dict):
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
                pass  # Silently ignore closed/filtered ports or timeouts
            finally:
                progress['scanned'] += 1

    async def process_files(self, file_paths: list, output_path: str, progress_callback):
        open_ips = []
        progress = {'scanned': 0, 'total': 0}
        
        # Pre-calculate total IPs for accurate progress tracking (memory efficient)
        for path in file_paths:
            async with aiofiles.open(path, 'r') as f:
                async for _ in f:
                    progress['total'] += 1

        last_report = asyncio.get_event_loop().time()

        for path in file_paths:
            tasks = []
            async with aiofiles.open(path, 'r') as f:
                async for line in f:
                    ip = line.strip()
                    if not ip:
                        continue
                    
                    tasks.append(self._check_port(ip, open_ips, progress))
                    
                    # Batch execution to prevent event loop overload and RAM spikes
                    if len(tasks) >= BATCH_SIZE:
                        await asyncio.gather(*tasks, return_exceptions=True)
                        tasks = []
                        
                        # Throttled progress reporting (every 5 seconds)
                        now = asyncio.get_event_loop().time()
                        if now - last_report > 5.0:
                            await progress_callback(progress['scanned'], progress['total'], len(open_ips))
                            last_report = now

            # Final batch for the current file
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        # Write results to disk efficiently
        async with aiofiles.open(output_path, 'w') as f:
            await f.write("\n".join(open_ips))
            
        return len(open_ips)

# ==================== 🤖 TELEGRAM BOT LOGIC ====================
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(storage=MemoryStorage())
engine = RDPEngine(max_concurrent=MAX_CONCURRENT_SCANS, timeout=TIMEOUT_SECONDS)

def get_raw_url(chunk_num: int) -> str:
    return f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/chunk_{chunk_num}.txt"

@dp.message(Command("start"))
async def cmd_start(message: types.Message, state: FSMContext):
    chat_id = message.chat.id
    user_dir = Path(f"temp_scan_{chat_id}")
    
    # Clean up any previous residual data
    if user_dir.exists():
        shutil.rmtree(user_dir)
    user_dir.mkdir(exist_ok=True)
    
    await state.set_state(ScanStates.ready)
    await message.answer(
        "🔐 **RDP Extraction Bot Initialized**\n\n"
        f"📂 Repository detected: `{REPO_OWNER}/{REPO_NAME}`\n"
        f"📦 Chunks to process: `{NUM_CHUNKS}`\n\n"
        "Send the `/scan` command to begin downloading and analyzing the targets. "
        "You will receive real-time progress updates and the final extracted file.",
        parse_mode="Markdown"
    )

@dp.message(Command("scan"))
async def cmd_scan(message: types.Message, state: FSMContext):
    chat_id = message.chat.id
    user_dir = Path(f"temp_scan_{chat_id}")
    output_file = user_dir / "open_rdp_results.txt"
    
    await state.set_state(ScanStates.scanning)
    await message.answer("⏳ **Phase 1:** Downloading chunks from GitHub repository...")

    # 1. Async Download Phase
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
                    else:
                        await message.answer(f"❌ Failed to download chunk_{i}.txt (HTTP {response.status})")
            except Exception as e:
                await message.answer(f"❌ Network error downloading chunk_{i}.txt: {e}")

    if not file_paths:
        await message.answer("🚫 Critical failure: No files were downloaded. Aborting.")
        await state.clear()
        return

    await message.answer(f"✅ **Phase 1 Complete.** {len(file_paths)} files downloaded.\n🚀 **Phase 2:** Initiating asynchronous port scan...")

    # 2. Scanning Phase (Background Task)
    async def report_progress(scanned, total, found):
        percent = (scanned / total) * 100 if total > 0 else 0
        try:
            await bot.send_message(
                chat_id,
                f"📊 **Scan Progress:** {percent:.1f}%\n"
                f"🔍 Processed: `{scanned:,}` / `{total:,}`\n"
                f"🔓 Open RDP Ports Found: `{found}`",
                parse_mode="Markdown"
            )
        except Exception:
            pass  # Ignore if the user blocked the bot mid-scan

    # Run in background to keep the bot responsive
    asyncio.create_task(_execute_scan(chat_id, file_paths, str(output_file), report_progress, state))

async def _execute_scan(chat_id: int, file_paths: list, output_path: str, progress_cb, state: FSMContext):
    try:
        found_count = await engine.process_files(file_paths, output_path, progress_cb)
        
        # 3. Delivery Phase
        if found_count > 0:
            with open(output_path, 'rb') as f:
                await bot.send_document(
                    chat_id,
                    f,
                    caption=f"🎯 **Scan Complete.**\n\nSuccessfully extracted `{found_count}` IP addresses with open RDP (Port 3389).",
                    visible_file_name="extracted_open_rdp_ips.txt"
                )
        else:
            await bot.send_message(chat_id, "🔍 Scan complete. No open RDP ports were found in the provided datasets.")
            
    except Exception as e:
        logging.error(f"Scan execution failed: {e}")
        await bot.send_message(chat_id, f"⚠️ An unexpected error occurred during scanning: {e}")
    finally:
        # 4. Cleanup Phase
        user_dir = Path(f"temp_scan_{chat_id}")
        if user_dir.exists():
            shutil.rmtree(user_dir)
        await state.clear()
        await bot.send_message(chat_id, "🧹 Temporary files have been securely purged from the system. Ready for the next operation (`/start`).")

# ==================== 🚀 ENTRY POINT ====================
async def main():
    logging.info("Initializing Elite RDP Extraction Bot...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Bot gracefully terminated.")
