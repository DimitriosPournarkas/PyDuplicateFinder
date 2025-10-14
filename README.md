CLI File Duplicate Finder

A lightweight command-line tool to find duplicate files in your directory structure. 
Supports two detection modes: fast (by file size and name) or accurate (by content hash).

Features:
- Recursively scan directories
- Find duplicates by size + name (fast)
- Verify by content hash (accurate)
- Detailed or compact output
- Color-coded results

Usage:
python dupes.py /path/to/directory
python dupes.py /path/to/directory --use-hash --detailed

Install:
pip install click
