import pandas as pd
import numpy as np
import os
from tqdm import tqdm

def label_attack_features(features, attack_logs, tolerance):
    print("Entering label_attack_features")
    features["label"] = 0
    chunk_size = 1_000_000
    
    attack_logs_unique = attack_logs.drop_duplicates(subset=["TargetIP", "Timestamp"])
    print(f"Unique attack logs rows: {len(attack_logs_unique)} (from {len(attack_logs)})")
    
    for start in range(0, len(features), chunk_size):
        end = min(start + chunk_size, len(features))
        chunk = features.iloc[start:end].copy()
        chunk["original_index"] = np.arange(start, end)
        
        merged = chunk.merge(
            attack_logs_unique[["Timestamp", "TargetIP"]],
            left_on=["dst_ip"],
            right_on=["TargetIP"],
            how="left"
        )
        
        mask = (
            (abs(merged["timestamp"] - merged["Timestamp"]) <= tolerance) &
            merged["Timestamp"].notna()
        )
        
        matched_indices = merged.loc[mask, "original_index"].unique()
        if len(matched_indices) > 0:
            print(f"Sample matched rows:\n{chunk.loc[chunk['original_index'].isin(matched_indices)].head()}")
        
        chunk.loc[chunk["original_index"].isin(matched_indices), "label"] = 1
        features.iloc[start:end, features.columns.get_loc("label")] = chunk["label"]
        
        print(f"Processed chunk {start}-{end}, matches: {len(matched_indices)}")
    
    print("Exiting label_attack_features")
    return features

# Compromised-scada features and labeling
print("Loading compromised-scada features...")
compromised_scada_features = pd.read_csv(
    "C:/Users/Benja/OneDrive/Documents/Projects/SNIF-L/features/attack_compromised-scada_features.csv",
    names=['packet_size', 'inter_arrival_time', 'protocol', 'dest_port', 'src_ip', 'dst_ip', 'timestamp', 'transaction_id']
)
print(f"Compromised-scada features loaded: {len(compromised_scada_features)} rows")

compromised_scada_attack_logs = pd.DataFrame({
    "Timestamp": [1678853471.1, 1678853472.1],  # 2023-03-15 04:51:11.1, 04:51:12.1 UTC
    "TargetIP": ["185.175.0.4", "185.175.0.4"]
})
print("Labeling compromised-scada features...")
labeled_compromised_scada = label_attack_features(compromised_scada_features, compromised_scada_attack_logs, tolerance=5.0)
print(f"Compromised-scada labeling complete with {labeled_compromised_scada['label'].sum()} attack labels")

# External features and labeling with ingested logs
print("Loading external features...")
external_features = pd.read_csv(
    "C:/Users/Benja/OneDrive/Documents/Projects/SNIF-L/features/attack_external_features.csv",
    names=['packet_size', 'inter_arrival_time', 'protocol', 'dest_port', 'src_ip', 'dst_ip', 'timestamp', 'transaction_id']
)
print(f"External features loaded: {len(external_features)} rows")

# Ingest external attack logs from the specified directory
external_logs_dir = "C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/datasets/CIC Modbus Dataset/attack/external/external-attacker/attacker logs"
external_attack_logs = pd.DataFrame(columns=['Timestamp', 'AttackType', 'TargetIP'])

for filename in os.listdir(external_logs_dir):
    if filename.endswith('.csv'):  # Adjust extension based on actual files
        file_path = os.path.join(external_logs_dir, filename)
        try:
            df = pd.read_csv(file_path)
            # Adjust column names based on snippet (Timestamp, AttackType)
            df = df.rename(columns={
                'Timestamp': 'Timestamp',  # Replace with actual column name
                'AttackType': 'AttackType',  # Replace with actual column name
                'TargetIP': 'TargetIP'  # Add if present, else infer
            })
            # Convert Timestamp to float (Unix epoch) if needed
            if df['Timestamp'].dtype == 'object':
                # Assuming MM:SS.t format relative to 2023-02-01 03:00:00 (tentative)
                base_time = 1675221600  # 2023-02-01 03:00:00 UTC
                df['Timestamp'] = df['Timestamp'].apply(lambda x: base_time + (pd.to_datetime(x, format='%M:%S.%f') - pd.to_datetime('00:00', format='%M:%S')).total_seconds())
            # Infer TargetIP as 185.175.0.4 if not present
            if 'TargetIP' not in df.columns:
                df['TargetIP'] = '185.175.0.4'
            external_attack_logs = pd.concat([external_attack_logs, df[['Timestamp', 'TargetIP']]], ignore_index=True)
        except Exception as e:
            print(f"Error reading {filename}: {e}")

print(f"External attack logs ingested: {len(external_attack_logs)} rows")

# Add specific log entries from the snippet
base_time = 1675221600  # 2023-02-01 03:00:00 UTC (adjust based on PCAP)
external_attack_logs = pd.concat([
    external_attack_logs,
    pd.DataFrame({
        "Timestamp": [
            base_time + (pd.to_datetime('38:50.7', format='%M:%S.%f') - pd.to_datetime('00:00', format='%M:%S')).total_seconds(),
            base_time + (pd.to_datetime('45:33.3', format='%M:%S.%f') - pd.to_datetime('00:00', format='%M:%S')).total_seconds()
        ],
        "TargetIP": ["185.175.0.4", "185.175.0.4"]
    })
], ignore_index=True)

print("Labeling external features...")
labeled_external = label_attack_features(external_features, external_attack_logs, tolerance=5.0)
print(f"External labeling complete with {labeled_external['label'].sum()} attack labels")

# Compromised-ied features and labeling
print("Loading compromised-ied features...")
compromised_ied_features = pd.read_csv(
    "C:/Users/Benja/OneDrive/Documents/Projects/SNIF-L/features/attack_compromised-ied_features.csv",
    names=['packet_size', 'inter_arrival_time', 'protocol', 'dest_port', 'src_ip', 'dst_ip', 'timestamp', 'transaction_id']
)
print(f"Compromised-ied features loaded: {len(compromised_ied_features)} rows")

compromised_ied_attack_logs = pd.DataFrame({
    "Timestamp": [1679583283.5],  # 2023-03-23 15:14:43.5 UTC
    "TargetIP": ["185.175.0.4"]
})
print("Labeling compromised-ied features...")
labeled_compromised_ied = label_attack_features(compromised_ied_features, compromised_ied_attack_logs, tolerance=5.0)
print(f"Compromised-ied labeling complete with {labeled_compromised_ied['label'].sum()} attack labels")

# Combine all labeled features
combined_features = pd.concat([labeled_compromised_scada, labeled_external, labeled_compromised_ied], ignore_index=True)
print(f"Combined features: {len(combined_features)} rows")

# Prepare training data
X = combined_features.drop(columns=['src_ip', 'dst_ip', 'label']).values
y = combined_features['label'].values

print("Saving training data...")
np.save("X_labeled.npy", X)
np.save("y_labeled.npy", y)
print("Training data saved")

# Optional: Verify a few labeled rows
print("Sample labeled data:")
print(combined_features.head())