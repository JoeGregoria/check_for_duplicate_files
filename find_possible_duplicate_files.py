import os
import hashlib
import csv
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import time
import argparse

tqdm_disable = True

def hash_file(filepath, partial_bytes, algorithm='sha256'):
    if algorithm == 'md5':
        hasher = hashlib.md5()
    elif algorithm == 'sha256':
        hasher = hashlib.sha256()
    else:
        raise ValueError("Unsupported hash algorithm")
    try:
        with open(filepath, 'rb') as f:
            buf = f.read(partial_bytes)
            hasher.update(buf)
    except Exception as e:
        return None, str(e)
    return hasher.hexdigest(), None

def get_file_info(filepath):
    stat = os.stat(filepath)
    return stat.st_size, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(stat.st_mtime))

def find_duplicate_groups(folder, partial_bytes, num_workers, algorithm):
    size_dict = defaultdict(list)
    for root, dirs, files in os.walk(folder):
        for filename in files:
            fullpath = os.path.join(root, filename)
            try:
                filesize = os.path.getsize(fullpath)
                size_dict[filesize].append(fullpath)
            except Exception as e:
                print(f"Could not access {fullpath}: {e}")
    hash_dict = defaultdict(list)
    for flist in size_dict.values():
        if len(flist) < 2:
            continue
        with ThreadPoolExecutor(max_workers=num_workers) as executor:
            future_to_file = {
                executor.submit(hash_file, filepath, partial_bytes, algorithm): filepath
                for filepath in flist
            }
            for future in tqdm(as_completed(future_to_file), total=len(flist), desc="Hashing files", disable=tqdm_disable):
                filepath = future_to_file[future]
                h, err = future.result()
                if h is not None:
                    hash_dict[h].append(filepath)
                else:
                    print(f"Could not hash {filepath}: {err}")
    duplicates = {h: group for h, group in hash_dict.items() if len(group) > 1}
    return duplicates

def summarize_top_duplicates(duplicates, topn=10):
    group_summaries = []
    for h, group in duplicates.items():
        size = 0
        sizes = []
        for filepath in group:
            try:
                sz, _ = get_file_info(filepath)
            except Exception:
                sz = 0
            size += sz
            sizes.append(sz)
        group_summaries.append((size, h, group, sizes))
    # Sort by total duplicate group size descending
    group_summaries.sort(reverse=True, key=lambda x: x[0])
    print("\nTop {} Duplicate Groups by Total Duplicate Size:".format(topn))
    for i, (size, h, group, sizes) in enumerate(group_summaries[:topn], start=1):
        size_gb = size / (1024 ** 3)
        print(f"\nGroup #{i} - Total Size: {size} bytes ({size_gb:.2f} GB) ({len(group)} files)")
        for fp, sz in zip(group, sizes):
            print(f"    {fp} ({sz} bytes)")
        print(f"  Hash (Partial): {h}")
    print('-' * 60)

def main():
    parser = argparse.ArgumentParser(description="Find duplicate files by partial hash and output results to CSV.")
    parser.add_argument("--scan_folder", metavar="FOLDER", default=os.getcwd(), help="Folder to scan for duplicate files")
    parser.add_argument("--output_csv", metavar="CSV_FILE", default="possible_duplicates.csv", help="CSV file to save duplicate information")
    parser.add_argument("--hash-size-mb", type=int, default=100, help="Bytes to hash per file in MB (default: 100) to make this go faster (partial hashing)")
    parser.add_argument("--algorithm", choices=["sha256", "md5"], default="sha256", help="Hash algorithm (sha256 or md5, default: sha256)")
    parser.add_argument("--topn", type=int, default=10, help="How many largest duplicate groups to print (default: 10)")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Threads to use for hashing (default: system CPU count)")
    args = parser.parse_args()

    partial_bytes = args.hash_size_mb * 1024 * 1024

    print(f"\nScanning '{args.scan_folder}' for duplicate files using partial {args.algorithm.upper()} hash...")
    print(f"Hash size: {args.hash_size_mb} MB per file. Workers: {args.workers}\n")
    duplicates = find_duplicate_groups(args.scan_folder, partial_bytes, args.workers, args.algorithm)

    if duplicates:
        summarize_top_duplicates(duplicates, topn=args.topn)
        with open(args.output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Duplicate Group Hash', 'File Path', 'File Size (bytes)', 'Last Modified'])
            for h, group in duplicates.items():
                for filepath in group:
                    try:
                        size, mod_time = get_file_info(filepath)
                    except Exception:
                        size, mod_time = 'ERROR', 'ERROR'
                    writer.writerow([h, filepath, size, mod_time])
        print(f"\nDone! Duplicate groups listed in '{args.output_csv}'.")
        print(f"Groups found: {len(duplicates)}\n")
    else:
        print("No duplicate groups found.")

if __name__ == "__main__":
    main()
