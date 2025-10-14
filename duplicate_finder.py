import os
import hashlib
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading


def get_file_hash(filepath, chunk_size=8192):
    """Calculate SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except (IOError, OSError):
        return None


def find_duplicates_by_size(directory):
    """Find potential duplicates by file size (first pass, fast)."""
    size_map = defaultdict(list)
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                size = os.path.getsize(filepath)
                size_map[size].append(filepath)
            except (IOError, OSError):
                continue
    
    potential_dupes = {k: v for k, v in size_map.items() if len(v) > 1}
    return potential_dupes


def find_duplicates_by_hash(filepaths):
    """Verify duplicates by content hash."""
    hash_map = defaultdict(list)
    
    for filepath in filepaths:
        file_hash = get_file_hash(filepath)
        if file_hash:
            hash_map[file_hash].append(filepath)
    
    duplicates = {k: v for k, v in hash_map.items() if len(v) > 1}
    return duplicates


class DuplicateFinderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Duplicate File Finder")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Directory selection frame
        frame_dir = tk.Frame(root)
        frame_dir.pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(frame_dir, text="Select Directory:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        
        self.dir_var = tk.StringVar()
        tk.Entry(frame_dir, textvariable=self.dir_var, width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_dir, text="Browse", command=self.browse_directory).pack(side=tk.LEFT)
        
        # Button frame
        frame_btn = tk.Frame(root)
        frame_btn.pack(pady=10)
        
        tk.Button(frame_btn, text="Scan", command=self.scan_duplicates, 
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_btn, text="Clear", command=self.clear_output, 
                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), 
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        # Output text area
        tk.Label(root, text="Results:", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 0))
        
        self.output_text = scrolledtext.ScrolledText(root, height=20, width=70, wrap=tk.WORD)
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(root, textvariable=self.status_var, bg="#f0f0f0", 
                relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, side=tk.BOTTOM)
    
    def browse_directory(self):
        directory = filedialog.askdirectory(title="Select Directory")
        if directory:
            self.dir_var.set(directory)
    
    def output(self, text):
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        self.root.update()
    
    def scan_duplicates(self):
        directory = self.dir_var.get()
        
        if not directory:
            messagebox.showerror("Error", "Please select a directory!")
            return
        
        if not os.path.isdir(directory):
            messagebox.showerror("Error", "Directory does not exist!")
            return
        
        # Run scan in separate thread to avoid freezing GUI
        thread = threading.Thread(target=self._perform_scan, args=(directory,))
        thread.start()
    
    def _perform_scan(self, directory):
        self.status_var.set("Scanning...")
        self.output_text.delete(1.0, tk.END)
        
        self.output(f"Scanning directory: {directory}\n")
        
        try:
            potential_dupes = find_duplicates_by_size(directory)
            
            if not potential_dupes:
                self.output("No duplicates found.")
                self.status_var.set("Ready - No duplicates found")
                return
            
            self.output("Verifying duplicates by content hash...\n")
            all_files = []
            for paths in potential_dupes.values():
                all_files.extend(paths)
            
            duplicates = find_duplicates_by_hash(all_files)
            
            if not duplicates:
                self.output("No actual duplicates found.")
                self.status_var.set("Ready - No duplicates found")
                return
            
            total_dupes = sum(len(paths) - 1 for paths in duplicates.values())
            self.output(f"Found {total_dupes} duplicate files:\n")
            self.output("=" * 70 + "\n")
            
            for i, (file_hash, paths) in enumerate(duplicates.items(), 1):
                self.output(f"\n{i}. Hash: {file_hash[:16]}...")
                for path in paths:
                    self.output(f"   - {path}")
            
            self.status_var.set(f"Ready - Found {total_dupes} duplicates")
        
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error")
    
    def clear_output(self):
        self.output_text.delete(1.0, tk.END)
        self.status_var.set("Ready")


if __name__ == '__main__':
    root = tk.Tk()
    app = DuplicateFinderGUI(root)
    root.mainloop()

#C:\GitHub\Duplicate_finder\test