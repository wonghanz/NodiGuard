"""
NodiGuard System Performance & Memory Optimizer.
Inspired by Windows PC Manager and Driver Booster architectures.
Provides:
1. Windows Native EmptyWorkingSet RAM compaction (reclaims inactive memory pages).
2. Local SLM VRAM Instant Purge (unloads Ollama GPU weights on task completion).
3. Temporary file and cache garbage collection.
"""

import os
import sys
import gc
import time
import requests
from typing import Dict, Any, Optional

class SystemOptimizer:
    def __init__(self, ollama_url: Optional[str] = None):
        # Default to safe localhost loopback or environment variable
        self.ollama_url = ollama_url or os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
        self.is_windows = sys.platform == "win32"
        self._last_activity = time.time()

    def touch(self):
        """Records activity to prevent premature idle optimizations."""
        self._last_activity = time.time()

    def optimize_ram(self) -> Dict[str, Any]:
        """
        Forces garbage collection and compacts OS process working set.
        On Windows, calls EmptyWorkingSet via psapi to release unreferenced pages.
        """
        mem_before_mb = 0.0
        mem_after_mb = 0.0
        flushed_native = False

        try:
            import psutil
            proc = psutil.Process(os.getpid())
            mem_before_mb = round(proc.memory_info().rss / (1024 * 1024), 2)
        except Exception:
            pass

        # 1. Standard Python garbage collection
        gc.collect()

        # 2. Windows Native API: EmptyWorkingSet
        if self.is_windows:
            try:
                import ctypes
                handle = ctypes.windll.kernel32.GetCurrentProcess()
                ctypes.windll.psapi.EmptyWorkingSet(handle)
                flushed_native = True
            except Exception:
                pass

        try:
            import psutil
            proc = psutil.Process(os.getpid())
            mem_after_mb = round(proc.memory_info().rss / (1024 * 1024), 2)
        except Exception:
            pass

        released_mb = max(0.0, round(mem_before_mb - mem_after_mb, 2))

        return {
            "status": "success",
            "mem_before_mb": mem_before_mb,
            "mem_after_mb": mem_after_mb,
            "released_ram_mb": released_mb,
            "windows_native_flush": flushed_native,
        }

    def purge_gpu_vram(self, model_name: str = "default") -> Dict[str, Any]:
        """
        Purges local SLM weights from GPU VRAM by notifying Ollama with keep_alive=0.
        Frees 8GB-16GB of VRAM for other demanding tasks (IDEs, gaming, 3D render).
        """
        t0 = time.time()
        try:
            res = requests.post(
                f"{self.ollama_url.rstrip('/')}/api/generate",
                json={"model": model_name, "keep_alive": 0},
                timeout=3
            )
            elapsed = round((time.time() - t0) * 1000, 2)
            if res.status_code == 200:
                return {
                    "status": "success",
                    "model_unloaded": model_name,
                    "elapsed_ms": elapsed,
                    "message": f"Successfully unloaded {model_name} from GPU VRAM."
                }
            else:
                return {
                    "status": "skipped",
                    "reason": f"Ollama returned HTTP {res.status_code}"
                }
        except Exception as e:
            return {
                "status": "skipped",
                "reason": f"Ollama service unreachable ({str(e)})"
            }

    def clean_temp_cache(self, target_dir: Optional[str] = None) -> Dict[str, Any]:
        """
        Safely purges temporary cache files from sandbox or temporary execution directories.
        """
        if not target_dir:
            target_dir = os.path.join(os.path.expanduser("~"), ".nodiguard", "cache")

        cleaned_files = 0
        cleaned_bytes = 0

        if os.path.exists(target_dir):
            for fname in os.listdir(target_dir):
                fpath = os.path.join(target_dir, fname)
                try:
                    if os.path.isfile(fpath):
                        cleaned_bytes += os.path.getsize(fpath)
                        os.remove(fpath)
                        cleaned_files += 1
                except Exception:
                    pass

        return {
            "status": "success",
            "cleaned_files": cleaned_files,
            "cleaned_kb": round(cleaned_bytes / 1024, 2)
        }
