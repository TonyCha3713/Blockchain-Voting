#!/usr/bin/python3
import sys
from pathlib import Path

def delete_in_subdirs(extensions):
    cwd = Path.cwd()
    for subdir in cwd.iterdir():
        if not subdir.is_dir():
            continue

        for f in subdir.rglob('*'):
            if f.is_file() and f.suffix.lower() in extensions:
                try:
                    f.unlink()
                    print(f"Deleted: {f}")
                except Exception as e:
                    print(f"Failed to delete {f}: {e}", file=sys.stderr)

if __name__ == "__main__":
    exts = {'.json', '.pem'}
    delete_in_subdirs(exts)
