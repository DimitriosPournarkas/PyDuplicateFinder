import os
import hashlib
from collections import defaultdict
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading


def get_file_hash(filepath, chunk_size=8192):
    """Calculate SHA256 hash of a file."""
    ### Initialize SHA256 hash object for secure file hashing
    sha256_hash = hashlib.sha256()
    try:
        ### Open file in binary mode for reading
        with open(filepath, "rb") as f:
            ### Read file in chunks to handle large files efficiently
            ### This prevents loading entire file into memory at once
            for chunk in iter(lambda: f.read(chunk_size), b""):
                sha256_hash.update(chunk)
        ### Return hexadecimal representation of the hash
        return sha256_hash.hexdigest()
    except (IOError, OSError):
        ### Return None if file cannot be read (permissions, not found, etc.)
        return None


def find_duplicates_by_size(directory):
    """Find potential duplicates by file size (first pass, fast)."""
    ### Create a dictionary mapping file sizes to lists of file paths
    ### This is a fast first pass to group files that might be duplicates
    size_map = defaultdict(list)
    
    ### Walk through directory tree recursively
    for root, dirs, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                ### Get file size in bytes
                size = os.path.getsize(filepath)
                ### Group files by their size
                size_map[size].append(filepath)
            except (IOError, OSError):
                ### Skip files that cannot be accessed
                continue
    
    ### Filter to only keep sizes that have multiple files
    ### These are potential duplicates that need hash verification
    potential_dupes = {k: v for k, v in size_map.items() if len(v) > 1}
    return potential_dupes


def find_duplicates_by_hash(filepaths):
    """Verify duplicates by content hash."""
    ### Create a dictionary mapping file hashes to lists of file paths
    ### This verifies actual duplicates by comparing file content
    hash_map = defaultdict(list)
    
    ### Calculate hash for each file
    for filepath in filepaths:
        file_hash = get_file_hash(filepath)
        if file_hash:
            ### Group files by their content hash
            hash_map[file_hash].append(filepath)
    
    ### Filter to only keep hashes that have multiple files
    ### These are confirmed duplicates with identical content
    duplicates = {k: v for k, v in hash_map.items() if len(v) > 1}
    return duplicates


class DuplicateFinderGUI:
    def __init__(self, root):
        ### Set up main window properties
        self.root = root
        self.root.title("Duplicate File Finder")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        ### Store found duplicates for later deletion
        self.duplicates = {}
        
        ### Directory selection frame - contains label, entry, and browse button
        frame_dir = tk.Frame(root)
        frame_dir.pack(pady=10, padx=10, fill=tk.X)
        
        tk.Label(frame_dir, text="Select Directory:", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        
        ### String variable to hold the selected directory path
        self.dir_var = tk.StringVar()
        tk.Entry(frame_dir, textvariable=self.dir_var, width=50).pack(side=tk.LEFT, padx=5)
        tk.Button(frame_dir, text="Browse", command=self.browse_directory).pack(side=tk.LEFT)
        
        ### Button frame - contains scan, delete, and clear buttons
        frame_btn = tk.Frame(root)
        frame_btn.pack(pady=10)
        
        ### Scan button - initiates the duplicate search process
        tk.Button(frame_btn, text="Scan", command=self.scan_duplicates, 
                 bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), 
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        ### Delete button - removes duplicate files (keeps one copy)
        tk.Button(frame_btn, text="Delete Duplicates", command=self.delete_duplicates, 
                 bg="#FF9800", fg="white", font=("Arial", 10, "bold"), 
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        ### Clear button - clears the output text area
        tk.Button(frame_btn, text="Clear", command=self.clear_output, 
                 bg="#f44336", fg="white", font=("Arial", 10, "bold"), 
                 padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        ### Output text area - displays scan results and deletion logs
        tk.Label(root, text="Results:", font=("Arial", 10, "bold")).pack(anchor=tk.W, padx=10, pady=(10, 0))
        
        ### Scrollable text widget for displaying results
        self.output_text = scrolledtext.ScrolledText(root, height=20, width=70, wrap=tk.WORD)
        self.output_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        ### Status bar - shows current operation status
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(root, textvariable=self.status_var, bg="#f0f0f0", 
                relief=tk.SUNKEN, anchor=tk.W).pack(fill=tk.X, side=tk.BOTTOM)
    
    def browse_directory(self):
        ### Open directory selection dialog
        directory = filedialog.askdirectory(title="Select Directory")
        if directory:
            ### Update the entry field with selected directory path
            self.dir_var.set(directory)
    
    def output(self, text):
        ### Insert text into the output area and auto-scroll to bottom
        self.output_text.insert(tk.END, text + "\n")
        self.output_text.see(tk.END)
        ### Update GUI to display new text immediately
        self.root.update()
    
    def scan_duplicates(self):
        ### Get the directory path from the entry field
        directory = self.dir_var.get()
        
        ### Validate that a directory has been selected
        if not directory:
            messagebox.showerror("Error", "Please select a directory!")
            return
        
        ### Validate that the directory exists
        if not os.path.isdir(directory):
            messagebox.showerror("Error", "Directory does not exist!")
            return
        
        ### Run scan in separate thread to avoid freezing the GUI
        ### This allows the UI to remain responsive during long scans
        thread = threading.Thread(target=self._perform_scan, args=(directory,))
        thread.start()
    
    def _perform_scan(self, directory):
        ### Update status bar to show scanning is in progress
        self.status_var.set("Scanning...")
        ### Clear previous results
        self.output_text.delete(1.0, tk.END)
        
        self.output(f"Scanning directory: {directory}\n")
        
        try:
            ### First pass: Group files by size (fast operation)
            potential_dupes = find_duplicates_by_size(directory)
            
            ### Check if any potential duplicates were found
            if not potential_dupes:
                self.output("No duplicates found.")
                self.status_var.set("Ready - No duplicates found")
                return
            
            ### Second pass: Verify duplicates by content hash (slower but accurate)
            self.output("Verifying duplicates by content hash...\n")
            ### Flatten the list of potential duplicate files
            all_files = []
            for paths in potential_dupes.values():
                all_files.extend(paths)
            
            ### Calculate hashes and find actual duplicates
            duplicates = find_duplicates_by_hash(all_files)
            
            ### Check if any actual duplicates were found after hash verification
            if not duplicates:
                self.output("No actual duplicates found.")
                self.status_var.set("Ready - No duplicates found")
                self.duplicates = {}
                return
            
            ### Store duplicates for potential deletion
            self.duplicates = duplicates
            
            ### Calculate total number of duplicate files (excluding the original)
            total_dupes = sum(len(paths) - 1 for paths in duplicates.values())
            self.output(f"Found {total_dupes} duplicate files:\n")
            self.output("=" * 70 + "\n")
            
            ### Display each group of duplicates with their hash
            for i, (file_hash, paths) in enumerate(duplicates.items(), 1):
                ### Show truncated hash for readability
                self.output(f"\n{i}. Hash: {file_hash[:16]}...")
                ### List all files with this hash
                for path in paths:
                    self.output(f"   - {path}")
            
            ### Update status bar with summary
            self.status_var.set(f"Ready - Found {total_dupes} duplicates")
        
        except Exception as e:
            ### Display error message if scan fails
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
            self.status_var.set("Error")
    
    def clear_output(self):
        ### Clear all text from the output area
        self.output_text.delete(1.0, tk.END)
        ### Reset status bar
        self.status_var.set("Ready")
    
    def delete_duplicates(self):
        ### Check if duplicates have been found
        if not self.duplicates:
            messagebox.showwarning("Warning", "No duplicates found yet! Please scan first.")
            return
        
        ### Calculate total number of files to be deleted
        total_dupes = sum(len(paths) - 1 for paths in self.duplicates.values())
        
        ### Show confirmation dialog with deletion details
        response = messagebox.askyesno(
            "Confirm Delete",
            f"This will delete {total_dupes} duplicate files.\n\n"
            f"One copy of each file will be kept.\n\n"
            f"Are you sure you want to continue?"
        )
        
        ### Exit if user cancels
        if not response:
            return
        
        ### Initialize counters for tracking deletion results
        deleted_count = 0
        errors = []
        
        ### Update status and output deletion header
        self.status_var.set("Deleting duplicates...")
        self.output("\n" + "=" * 70)
        self.output("DELETION PROCESS:")
        self.output("=" * 70 + "\n")
        
        ### Process each group of duplicate files
        for file_hash, paths in self.duplicates.items():
            ### Keep the first file, delete all others
            kept_file = paths[0]
            self.output(f"Keeping: {kept_file}")
            
            ### Delete all duplicate copies
            for duplicate in paths[1:]:
                try:
                    ### Permanently delete the duplicate file
                    os.remove(duplicate)
                    self.output(f"  Deleted: {duplicate}")
                    deleted_count += 1
                except Exception as e:
                    ### Log any errors during deletion
                    error_msg = f"  Error deleting {duplicate}: {str(e)}"
                    self.output(error_msg)
                    errors.append(error_msg)
            
            self.output("")
        
        ### Display deletion summary
        self.output("=" * 70)
        self.output(f"SUMMARY: {deleted_count} files deleted successfully.")
        if errors:
            self.output(f"Errors: {len(errors)} files could not be deleted.")
        
        ### Update status bar
        self.status_var.set(f"Deleted {deleted_count} duplicates")
        ### Clear stored duplicates after deletion
        self.duplicates = {}
        
        ### Show appropriate completion message
        if errors:
            messagebox.showwarning(
                "Deletion Complete with Errors",
                f"Deleted {deleted_count} files.\n{len(errors)} files could not be deleted."
            )
        else:
            messagebox.showinfo("Success", f"Successfully deleted {deleted_count} duplicate files!")


### Entry point - create and run the application
if __name__ == '__main__':
    root = tk.Tk()
    app = DuplicateFinderGUI(root)
    root.mainloop()

