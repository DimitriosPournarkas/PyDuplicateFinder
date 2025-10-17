# GUI File Duplicate Finder

A user-friendly graphical tool to find and remove duplicate files in your directory structure.
Uses a two-pass detection method: fast file size comparison followed by SHA256 content hash verification.

## Features

- **Graphical User Interface** - Easy-to-use tkinter-based GUI
- **Two-pass detection algorithm**:
  1. Fast first pass: Groups files by size
  2. Accurate second pass: Verifies duplicates with SHA256 hash
- **Safe deletion** - Always keeps one copy of each file
- **Non-blocking scan** - Threaded scanning keeps GUI responsive
- **Detailed results** - Shows all duplicate file locations
- **Confirmation dialogs** - Prevents accidental deletions

## Requirements

- Python 3.x
- tkinter (usually included with Python)
- No external dependencies needed

## Usage

1. Run the application:
```bash
