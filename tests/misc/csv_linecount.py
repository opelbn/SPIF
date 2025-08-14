import os
import glob

input_dir = "C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/data/features/"
csv_files = glob.glob(os.path.join(input_dir, "*.csv"))

total_lines = 0
for csv_file in csv_files:
    with open(csv_file, 'r') as f:
        line_count = sum(1 for line in f)
    print(f"{csv_file}: {line_count} lines")
    total_lines += line_count

print(f"Total lines across all CSVs: {total_lines}")
print(f"Total data lines (excluding headers): {total_lines - len(csv_files)}")