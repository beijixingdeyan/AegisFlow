"""Minimal test runner — no external dependencies (stdlib unittest).

用法：
    python run_tests.py            # 运行全部测试
    python run_tests.py -v         # 详细输出

若已安装 pytest，也可直接 `pytest`（tests/ 下同一批测试以 unittest.TestCase 编写，
pytest 完全兼容）。
"""

import os
import sys
import unittest


def main() -> int:
    tests_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=tests_dir, pattern="test_*.py")
    verbosity = 2 if "-v" in sys.argv else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
