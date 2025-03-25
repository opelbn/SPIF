import pandas as pd
import xgboost as xgb
from tqdm import tqdm

feature_names = ['packet_size', 'inter_arrival_time', 'protocol', 'dest_port', 'timestamp', 'transaction_id']
test_packets = pd.DataFrame([
    [74, 0.03, 6, 502, 1.679540e+09, 0],       # Benign-like
    [66, 0.02, 6, 502, 1.678638e+09, 5],       # Attack-like
    [78, 0.10, 6, 502, 1.679850e+09, 64791],   # Edge case
    [60, 0.01, 6, 80, 1.679540e+09, 0],        # Non-Modbus
], columns=feature_names)

print("Preparing test packets...")
dtest_packets = xgb.DMatrix(test_packets)
print("Test packets ready")

print("Loading model...")
bst = xgb.Booster()
bst.load_model('xgboost_model_cuda.json')  # Corrected loading method
print("Model loaded")

print("Predicting on test packets...")
predictions = bst.predict(dtest_packets)
labels = (predictions > 0.5).astype(int)

test_packets['predicted_label'] = labels
test_packets['probability'] = predictions
print("Test Packet Predictions:")
for i, row in test_packets.iterrows():
    print(f"Packet {i + 1}/{len(test_packets)}:")
    print(row)
    print("-" * 50)

print("All predictions complete")