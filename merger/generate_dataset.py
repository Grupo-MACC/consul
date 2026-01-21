#!/usr/bin/env python3
import sys
sys.path.insert(0, '/app')
from windowed_dataset import generate_windowed_dataset

print("[*] Generating windowed dataset from /zeek_logs...")
try:
    result = generate_windowed_dataset()
    print(f"\n✅ Dataset successfully generated!")
    print(f"   Exported to: {result}")
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
