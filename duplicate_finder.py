import os
import hashlib
from collections import defaultdict
from pathlib import Path
import click


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
    
    # Filter to only files with same size
    potential_dupes = {k: v for k, v in size_map.items() if len(v) > 1}
    return potential_dupes


def find_duplicates_by_hash(filepaths):
    """Verify duplicates by content hash."""
    hash_map = defaultdict(list)
    
    for filepath in filepaths:
        file_hash = get_file_hash(filepath)
        if file_hash:
            hash_map[file_hash].append(filepath)
    
    # Filter to only actual duplicates
    duplicates = {k: v for k, v in hash_map.items() if len(v) > 1}
    return duplicates


@click.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False), required=False)
@click.option('--use-hash', is_flag=True, help='Verify duplicates by content hash (slower but accurate)')
@click.option('--detailed', is_flag=True, help='Show full file paths')
def find_dupes(directory, use_hash, detailed):
    """Find duplicate files in a directory."""
    
    # Prompt user for directory if not provided
    if not directory:
        directory = click.prompt('Enter directory path')
        if not os.path.isdir(directory):
            click.secho("Error: Directory does not exist!", fg='red')
            return
    
    click.echo(f"Scanning directory: {directory}")
    click.echo()
    
    # First pass: find by size
    potential_dupes = find_duplicates_by_size(directory)
    
    if not potential_dupes:
        click.echo("No duplicates found.")
        return
    
    # Second pass: verify by hash (to find actual duplicates)
    click.echo("Verifying duplicates by content hash...\n")
    all_files = []
    for paths in potential_dupes.values():
        all_files.extend(paths)
    
    duplicates = find_duplicates_by_hash(all_files)
    
    if not duplicates:
        click.echo("No actual duplicates found.")
        return
    
    # Display results
    total_dupes = sum(len(paths) - 1 for paths in duplicates.values())
    click.echo(f"Found {total_dupes} duplicate files:\n")
    
    for i, (key, paths) in enumerate(duplicates.items(), 1):
        file_hash = key
        click.secho(f"{i}. Hash: {file_hash[:16]}...", fg='yellow', bold=True)
        
        for path in paths:
            if detailed:
                click.echo(f"   - {path}")
            else:
                click.echo(f"   - {Path(path).name} in {Path(path).parent}")
        click.echo()


if __name__ == '__main__':
    find_dupes()