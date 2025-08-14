import os
import glob
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def count_labels_in_file(file_path):
    """
    Count 'Malicious' and 'Benign' labels in a single conn.log.labeled file.
    Returns (malicious_count, benign_count).
    """
    malicious_count = 0
    benign_count = 0
    data_lines = 0
    comment_lines = 0

    logger.info(f"Processing file: {file_path}")
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip() == "" or line.startswith('#'):
                comment_lines += 1
                continue

            data_lines += 1
            # Split on tabs, last field is the label field
            fields = line.strip().split('\t')
            if len(fields) < 21:  # Ensure the line has enough fields
                logger.warning(f"Skipping malformed line in {file_path}: {line.strip()}")
                continue

            # Last field is the label field (e.g., "-   Malicious   C&C")
            label_field = fields[-1]
            # Split the label field on spaces
            label_parts = label_field.split()
            if len(label_parts) < 2:
                logger.warning(f"Skipping malformed label field in {file_path}: {label_field}")
                continue

            # Second part should be "Malicious" or "Benign"
            label = label_parts[1].lower()
            if label == "malicious":
                malicious_count += 1
            elif label == "benign":
                benign_count += 1
            else:
                logger.warning(f"Unknown label in {file_path}: {label_field}")

    logger.info(f"File: {file_path}")
    logger.info(f"Data lines: {data_lines}, Comment lines: {comment_lines}")
    logger.info(f"Malicious: {malicious_count}, Benign: {benign_count}")
    return malicious_count, benign_count

def count_labels_in_dataset(dataset_path):
    """
    Count labels across all conn.log.labeled files in the dataset directory.
    """
    # Find all conn.log.labeled files
    log_files = glob.glob(os.path.join(dataset_path, "**/conn.log.labeled"), recursive=True)
    logger.info(f"Found {len(log_files)} log files")

    total_malicious = 0
    total_benign = 0
    file_counts = []

    for file_path in log_files:
        m_count, b_count = count_labels_in_file(file_path)
        file_counts.append((file_path, m_count, b_count))
        total_malicious += m_count
        total_benign += b_count

    # Summary
    total_samples = total_malicious + total_benign
    logger.info("\n=== Summary ===")
    logger.info(f"Total files processed: {len(file_counts)}")
    logger.info(f"Total samples: {total_samples}")
    logger.info(f"Total Malicious: {total_malicious} ({total_malicious/total_samples*100:.2f}%)")
    logger.info(f"Total Benign: {total_benign} ({total_benign/total_samples*100:.2f}%)")
    logger.info("\nPer-file breakdown:")
    for file_path, m_count, b_count in file_counts:
        logger.info(f"{file_path}: Malicious={m_count}, Benign={b_count}")

if __name__ == "__main__":
    dataset_path = "D:/Datasets/iot_23_datasets_small/opt/Malware-Project/BigDataset/IoTScenarios"
    count_labels_in_dataset(dataset_path)