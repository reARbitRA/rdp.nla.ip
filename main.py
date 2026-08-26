#!/usr/bin/env python3
"""
RDP Extraction Engine - Enterprise/Systems Flagship Synthesis
=============================================================
Architecture:
  - Non-blocking raw socket multiplexing (Zero-Stream overhead)
  - Memory-bounded Worker-Pool Queue pattern
  - Dynamic POSIX socket limit adjustment (ulimit / RLIMIT_NOFILE)
  - Isolated multi-tenant state handling (Race-condition free)
  - Adaptive Telegram API rate-limit management
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import socket
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import AsyncGenerator, Optional, Set

# Optional POSIX resource tuning
try:
    import resource
except ImportError:
    resource = None

import aiofiles
import aiohttp
from aiogram import Bot, Dispatcher, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.exceptions import TelegramBadRequest, TelegramRetryAfter
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

# ==================== ⚙️ SYSTEM & CONFIGURATION ====================

def tune_system_limits(target_nofile: int = 65535) -> None:
    """Raise POSIX open file descriptor limit to avoid exhaustion under high concurrency."""
    if resource is None:
        return
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        new_soft = min(target_nofile, hard)
        if new_soft > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft, hard))
            logging.info(f"System RLIMIT_NOFILE tuned: {soft} -> {new_soft}")
    except Exception as e:
        logging.warning(f"Could not adjust system resource limits: {e}")

@dataclass(frozen=True)
class RuntimeConfig:
    bot_token: str = os.getenv("BOT_TOKEN", "8957022606:AAFcbxUXol4pgERaHLDI-d-ZRlPZNXvxZM0")
    repo_owner: str = "reARbitRA"
    repo_name: str = "rdp.nla.ip"
    branch: str = "main"
    num_chunks: int = 9
    
    # Engine Tuning
    max_workers: int = 800
    connect_timeout: float = 2.0
    queue_buffer_size: int = 4000
    progress_interval: float = 4.0
    download_retries: int = 3

CONFIG = RuntimeConfig()
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)

# ==================== 📊 ENGINE CORE MODELS ====================

class PipelinePhase(Enum):
    IDLE = auto()
    DOWNLOADING = auto()
    ANALYZING = auto()
    SCANNING = auto()
    FINALIZING = auto()
    ABORTED = auto()

@dataclass
class ScanTelemetry:
    scanned: int = 0
    total: int = 0
    found: int = 0
    start_time: float = field(default_factory=time.monotonic)

    @property
    def elapsed(self) -> float:
        return max(0.001, time.monotonic() - self.start_time)

    @property
    def ips_per_second(self) -> float:
        return self.scanned / self.elapsed

    @property
    def progress_percent(self) -> float:
        return (self.scanned / self.total * 100.0) if self.total > 0 else 0.0

    @property
    def eta_seconds(self) -> Optional[float]:
        if self.progress_percent < 0.5 or self.ips_per_second <= 0:
            return None
        return (self.total - self.scanned) / self.ips_per_second

# ==================== ⚡ ZERO-STREAM RAW SOCKET PROBER ====================

class SocketProber:
    """Ultra-low overhead TCP prober executing directly on loop socket primitives."""
    
    RDP_PORT = 3389

    @staticmethod
    def is_ipv4(address: str) -> bool:
        """Fast binary IPv4 validation avoiding getaddrinfo thread execution."""
        try:
            socket.inet_aton(address)
            return address.count('.') == 3
        except OSError:
            return False

    @classmethod
    async def probe(cls, ip: str, loop: asyncio.AbstractEventLoop, timeout: float) -> bool:
        """Non-blocking TCP handshake check without stream/protocol overhead."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (ip, cls.RDP_PORT)),
                timeout=timeout
            )
            return True
        except (OSError, asyncio.TimeoutError):
            return False
        finally:
            sock.close()

# ==================== 🚀 BOUNDED PIPELINE SCANNER ====================

class ScanContext:
    """Encapsulates state, buffers, and workers for an individual scan session."""

    def __init__(self, chat_id: int, base_dir: Path, config: RuntimeConfig):
        self.chat_id = chat_id
        self.work_dir = base_dir / f"session_{chat_id}"
        self.output_file = self.work_dir / "open_rdp_verified.txt"
        self.config = config
        self.cancel_event = asyncio.Event()
        self.telemetry = ScanTelemetry()
        self.phase = PipelinePhase.IDLE
        self.status_message: Optional[types.Message] = None
        self.active_task: Optional[asyncio.Task] = None
        self.results: Set[str] = set()

    def abort(self) -> None:
        self.cancel_event.set()
        if self.active_task and not self.active_task.done():
            self.active_task.cancel()

    def teardown(self) -> None:
        self.abort()
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)

class HighThroughputScanner:
    """Core engine managing worker pools and zero-copy chunk streaming."""

    def __init__(self, config: RuntimeConfig):
        self.config = config

    async def _worker(
        self,
        queue: asyncio.Queue[Optional[str]],
        context: ScanContext,
        loop: asyncio.AbstractEventLoop
    ) -> None:
        """Persistent worker extracting work units from a bounded queue."""
        while not context.cancel_event.is_set():
            try:
                ip = await queue.get()
                if ip is None:
                    queue.task_done()
                    break

                is_open = await SocketProber.probe(ip, loop, self.config.connect_timeout)
                if is_open:
                    context.results.add(ip)
                    context.telemetry.found += 1

                context.telemetry.scanned += 1
                queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.debug(f"Unhandled worker exception on probe: {e}")
                queue.task_done()

    async def execute_scan(
        self,
        context: ScanContext,
        files: list[Path],
        render_callback
    ) -> Set[str]:
        loop = asyncio.get_running_loop()
        context.telemetry = ScanTelemetry()
        context.phase = PipelinePhase.ANALYZING

        # Pass 1: Streaming line count
        await render_callback()
        total_ips = 0
        for fpath in files:
            if context.cancel_event.is_set():
                return set()
            async with aiofiles.open(fpath, mode="r", encoding="utf-8", errors="ignore") as af:
                async for line in af:
                    cleaned = line.strip()
                    if cleaned and SocketProber.is_ipv4(cleaned):
                        total_ips += 1

        context.telemetry.total = total_ips
        context.phase = PipelinePhase.SCANNING
        context.telemetry.start_time = time.monotonic()

        # Pass 2: Concurrency execution through bounded queue
        queue: asyncio.Queue[Optional[str]] = asyncio.Queue(maxsize=self.config.queue_buffer_size)
        workers = [
            asyncio.create_task(self._worker(queue, context, loop))
            for _ in range(self.config.max_workers)
        ]

        last_update = time.monotonic()

        async def feeder():
            for fpath in files:
                if context.cancel_event.is_set():
                    break
                async with aiofiles.open(fpath, mode="r", encoding="utf-8", errors="ignore") as af:
                    async for line in af:
                        if context.cancel_event.is_set():
                            break
                        ip = line.strip()
                        if ip and SocketProber.is_ipv4(ip):
                            await queue.put(ip)
            
            # Send stop signals to workers
            for _ in range(self.config.max_workers):
                await queue.put(None)

        feeder_task = asyncio.create_task(feeder())

        # Render loop
        while not feeder_task.done() or not queue.empty():
            if context.cancel_event.is_set():
                break
            now = time.monotonic()
            if now - last_update >= self.config.progress_interval:
                await render_callback()
                last_update = now
            await asyncio.sleep(0.5)

        await feeder_task
        await asyncio.gather(*workers, return_exceptions=True)

        if not context.cancel_event.is_set():
            context.phase = PipelinePhase.FINALIZING
            await render_callback()
            # Disk persistence
            context.work_dir.mkdir(parents=True, exist_ok=True)
            async with aiofiles.open(context.output_file, "w", encoding="utf-8") as out:
                for valid_ip in sorted(context.results):
                    await out.write(f"{valid_ip}\n")

        return context.results

# ==================== 🌐 RESILIENT DATA INGESTION ====================

class ResilientDownloader:
    """Asynchronous HTTP download manager with retry logic and stream writing."""

    def __init__(self, config: RuntimeConfig):
        self.config = config

    def _build_url(self, chunk_index: int) -> str:
        return (
            f"https://raw.githubusercontent.com/{self.config.repo_owner}/"
            f"{self.config.repo_name}/{self.config.branch}/chunk_{chunk_index}.txt"
        )

    async def fetch_chunk(
        self,
        session: aiohttp.ClientSession,
        chunk_idx: int,
        dest_path: Path
    ) -> bool:
        url = self._build_url(chunk_idx)
        for attempt in range(1, self.config.download_retries + 1):
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=45)) as resp:
                    if resp.status == 200:
                        async with aiofiles.open(dest_path, "wb") as f:
                            while chunk := await resp.content.read(65536):
                                await f.write(chunk)
                        return True
            except (aiohttp.ClientError, asyncio.TimeoutError):
                await asyncio.sleep(1.5 ** attempt)
        return False

# ==================== 🤖 TELEGRAM BOT CONTROLLER ====================

class ScanStates(StatesGroup):
    idle = State()
    running = State()

class RDPBotService:
    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.bot = Bot(
            token=config.bot_token,
            default_properties=DefaultBotProperties(parse_mode=ParseMode.MARKDOWN)
        )
        self.dp = Dispatcher(storage=MemoryStorage())
        self.scanner = HighThroughputScanner(config)
        self.downloader = ResilientDownloader(config)
        self.sessions: dict[int, ScanContext] = {}
        self.base_dir = Path("scanner_runtime")
        self.base_dir.mkdir(exist_ok=True)

        self._bind_routes()

    def _bind_routes(self) -> None:
        self.dp.message.register(self.handle_start, Command("start"))
        self.dp.message.register(self.handle_scan, Command("scan"))
        self.dp.message.register(self.handle_cancel, Command("cancel"))
        self.dp.message.register(self.handle_status, Command("status"))
        self.dp.message.register(self.handle_help, Command("help"))

    def _render_dashboard(self, ctx: ScanContext) -> str:
        def time_fmt(secs: float) -> str:
            if secs < 0: return "00:00:00"
            m, s = divmod(int(secs), 60)
            h, m = divmod(m, 60)
            return f"{h:02d}:{m:02d}:{s:02d}"

        t = ctx.telemetry
        if ctx.phase == PipelinePhase.DOWNLOADING:
            return "📥 **Phase 1/4: Ingesting dataset chunks from remote...**"
        if ctx.phase == PipelinePhase.ANALYZING:
            return "🔢 **Phase 2/4: Memory profiling & IPv4 validation stream...**"
        if ctx.phase == PipelinePhase.SCANNING:
            eta = time_fmt(t.eta_seconds) if t.eta_seconds else "calculating..."
            fill = int(t.progress_percent / 5)
            bar = "█" * fill + "░" * (20 - fill)
            return (
                "⚡ **Phase 3/4: High-Concurrency Probe Execution**\n\n"
                f"Progress: `[{bar}]` `{t.progress_percent:.1f}%`\n"
                f"⏱️ Elapsed: `{time_fmt(t.elapsed)}` | ETA: `{eta}`\n"
                f"🚀 Throughput: `{t.ips_per_second:,.0f} pkt/s`\n"
                f"🔍 Processed: `{t.scanned:,}` / `{t.total:,}`\n"
                f"🔓 **Verified Active RDP: `{t.found:,}`**\n\n"
                "🛑 Send /cancel to interrupt cleanly."
            )
        if ctx.phase == PipelinePhase.FINALIZING:
            return "💾 **Phase 4/4: Flushing targets to verified disk report...**"
        return "ℹ️ Engine idle."

    async def _safe_update_ui(self, ctx: ScanContext) -> None:
        """Throttle-aware Telegram UI updater with exponential backoff handling."""
        if not ctx.status_message:
            return
        text = self._render_dashboard(ctx)
        try:
            await ctx.status_message.edit_text(text)
        except TelegramRetryAfter as e:
            await asyncio.sleep(e.retry_after + 0.1)
        except TelegramBadRequest as e:
            if "message is not modified" not in str(e).lower():
                logging.debug(f"Telegram bad request ignored: {e}")
        except Exception as e:
            logging.debug(f"UI update suppressed: {e}")

    # ==================== CONTROLLER ACTIONS ====================

    async def handle_start(self, message: types.Message, state: FSMContext) -> None:
        chat_id = message.chat.id
        if chat_id in self.sessions:
            self.sessions[chat_id].teardown()
            del self.sessions[chat_id]

        await state.set_state(ScanStates.idle)
        await message.answer(
            "🛡️ **Enterprise RDP Concurrency Engine**\n\n"
            f"• Concurrency limit: `{self.config.max_workers}` sockets\n"
            f"• Probe timeout: `{self.config.connect_timeout}s`\n"
            f"• I/O Driver: `Raw Non-Blocking POSIX`\n\n"
            "Commands:\n"
            "/scan - Initiate extraction pipeline\n"
            "/cancel - Clean hardware abort\n"
            "/status - Real-time telemetry inspect\n"
            "/help - Architecture specification"
        )

    async def handle_scan(self, message: types.Message, state: FSMContext) -> None:
        chat_id = message.chat.id
        session = self.sessions.get(chat_id)
        
        if session and session.phase in (PipelinePhase.DOWNLOADING, PipelinePhase.SCANNING):
            await message.answer("⚠️ Active scan currently executing. Use /cancel to abort.")
            return

        session = ScanContext(chat_id, self.base_dir, self.config)
        self.sessions[chat_id] = session
        await state.set_state(ScanStates.running)

        session.status_message = await message.answer("⏳ Allocating engine context...")
        session.active_task = asyncio.create_task(self._orchestrate_pipeline(session, state))

    async def _orchestrate_pipeline(self, ctx: ScanContext, state: FSMContext) -> None:
        try:
            ctx.phase = PipelinePhase.DOWNLOADING
            ctx.work_dir.mkdir(parents=True, exist_ok=True)
            await self._safe_update_ui(ctx)

            # Phase 1: Ingestion
            downloaded_files: list[Path] = []
            connector = aiohttp.TCPConnector(limit=10, ttl_dns_cache=300)
            async with aiohttp.ClientSession(connector=connector) as http_sess:
                for idx in range(1, self.config.num_chunks + 1):
                    if ctx.cancel_event.is_set():
                        return
                    target_file = ctx.work_dir / f"chunk_{idx}.txt"
                    ok = await self.downloader.fetch_chunk(http_sess, idx, target_file)
                    if ok:
                        downloaded_files.append(target_file)

            if not downloaded_files or ctx.cancel_event.is_set():
                if not ctx.cancel_event.is_set():
                    await ctx.status_message.edit_text("❌ Network error: Unable to ingest source chunks.")
                return

            # Phase 2 & 3: Scan Engine
            results = await self.scanner.execute_scan(
                ctx,
                downloaded_files,
                lambda: self._safe_update_ui(ctx)
            )

            if ctx.cancel_event.is_set():
                return

            # Phase 4: Delivery
            if results and ctx.output_file.exists():
                doc = types.FSInputFile(ctx.output_file, filename="rdp_verified_hosts.txt")
                await self.bot.send_document(
                    ctx.chat_id,
                    document=doc,
                    caption=(
                        "✅ **Extraction Pipeline Complete**\n\n"
                        f"• Open RDP Hosts: `{len(results):,}`\n"
                        f"• Total Processed: `{ctx.telemetry.total:,}`\n"
                        f"• Run Duration: `{int(ctx.telemetry.elapsed)}s`"
                    )
                )
            else:
                await self.bot.send_message(ctx.chat_id, "🔍 Scan complete: No open RDP ports identified.")

        except asyncio.CancelledError:
            logging.info(f"Pipeline cancelled for chat {ctx.chat_id}")
        except Exception as e:
            logging.error(f"Fatal pipeline error: {e}", exc_info=True)
            with contextlib.suppress(Exception):
                await self.bot.send_message(ctx.chat_id, f"🚨 Critical execution fault: `{e}`")
        finally:
            ctx.teardown()
            self.sessions.pop(ctx.chat_id, None)
            await state.clear()

    async def handle_cancel(self, message: types.Message, state: FSMContext) -> None:
        chat_id = message.chat.id
        session = self.sessions.get(chat_id)
        if not session:
            await message.answer("ℹ️ No active operations found.")
            return

        session.abort()
        await message.answer("🛑 Interrupt signal acknowledged. Resources reclaimed.")
        await state.clear()

    async def handle_status(self, message: types.Message) -> None:
        session = self.sessions.get(message.chat.id)
        if not session or session.phase == PipelinePhase.IDLE:
            await message.answer("📊 System is idle. Ready for operations.")
            return
        await message.answer(self._render_dashboard(session))

    async def handle_help(self, message: types.Message) -> None:
        await message.answer(
            "📖 **Engine Specification**\n\n"
            "This engine utilizes a custom asynchronous socket multiplexer. "
            "Instead of maintaining high-level HTTP/Stream wrappers, it binds low-level "
            "POSIX non-blocking sockets directly to the event loop's notification triggers "
            "(`epoll`/`kqueue`), reducing execution overhead to bare hardware minimums."
        )

    async def run(self) -> None:
        tune_system_limits()
        logging.info("Starting engine polling...")
        await self.dp.start_polling(self.bot)

# ==================== 🏁 SYSTEM BOOTSTRAP ====================

def main():
    # Attempt uvloop initialization for near-native C event loop speed
    try:
        import uvloop
        uvloop.install()
        logging.info("⚡ Ultra-high-speed uvloop driver registered.")
    except ImportError:
        logging.info("ℹ️ Running standard asyncio event loop.")

    service = RDPBotService(CONFIG)
    try:
        asyncio.run(service.run())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Clean application shutdown.")

if __name__ == "__main__":
    main()
