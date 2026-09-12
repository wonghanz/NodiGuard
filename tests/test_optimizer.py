import unittest
from nodiguard.optimizer import SystemOptimizer

class TestSystemOptimizer(unittest.TestCase):
    def setUp(self):
        self.optimizer = SystemOptimizer()

    def test_ram_compaction(self):
        res = self.optimizer.optimize_ram()
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["mem_before_mb"], 0.0)
        self.assertGreaterEqual(res["mem_after_mb"], 0.0)
        self.assertGreaterEqual(res["released_ram_mb"], 0.0)

    def test_vram_purge_graceful_handling(self):
        # Pointing to an offline dummy port should gracefully skip and not crash
        offline_optimizer = SystemOptimizer(ollama_url="http://127.0.0.1:59999")
        res = offline_optimizer.purge_gpu_vram(model_name="test-model")
        self.assertEqual(res["status"], "skipped")
        self.assertIn("reason", res)

    def test_temp_cache_cleaning(self):
        res = self.optimizer.clean_temp_cache()
        self.assertEqual(res["status"], "success")
        self.assertGreaterEqual(res["cleaned_files"], 0)

if __name__ == "__main__":
    unittest.main()
