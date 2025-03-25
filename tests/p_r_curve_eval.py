import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_curve, f1_score
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load the test set
logger.info("Loading test set...")
X_test_full = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/X_test.npy")
y_test_full = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/y_test.npy")
dtest = xgb.DMatrix(X_test_full, label=y_test_full)

# Load the trained model
bst = xgb.Booster()
bst.load_model("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/models/xgboost_zeek_IoT_model_cuda_balanced.json")

# Predict probabilities
logger.info("Predicting probabilities...")
y_pred_proba = bst.predict(dtest)

# Compute precision-recall curve
logger.info("Computing precision-recall curve...")
precision, recall, thresholds = precision_recall_curve(y_test_full, y_pred_proba)

# Compute macro F1-score for each threshold
macro_f1_scores = []
for threshold in thresholds:
    y_pred = (y_pred_proba > threshold).astype(int)
    report = classification_report(y_test_full, y_pred, output_dict=True, zero_division=0)
    macro_f1 = (report['0.0']['f1-score'] + report['1.0']['f1-score']) / 2
    macro_f1_scores.append(macro_f1)

# Find the threshold that maximizes macro F1-score
optimal_idx = np.argmax(macro_f1_scores)
optimal_threshold = thresholds[optimal_idx]
logger.info(f"Optimal threshold for macro F1-score: {optimal_threshold}")

# Predict with the optimal threshold
y_pred_optimal = (y_pred_proba > optimal_threshold).astype(int)
logger.info("Classification Report with Optimal Threshold:")
logger.info(classification_report(y_test_full, y_pred_optimal))
logger.info("Confusion Matrix with Optimal Threshold:")
logger.info(confusion_matrix(y_test_full, y_pred_optimal))

# Additional evaluation: Minimize false negatives while keeping false positives reasonable
# Try a threshold that achieves 99% malicious recall
target_recall = 0.99
for i, r in enumerate(recall[:-1]):  # Exclude the last point (recall=0)
    if r >= target_recall:
        threshold_99_recall = thresholds[i]
        break

y_pred_99_recall = (y_pred_proba > threshold_99_recall).astype(int)
logger.info(f"Threshold for 99% malicious recall: {threshold_99_recall}")
logger.info("Classification Report for 99% Malicious Recall:")
logger.info(classification_report(y_test_full, y_pred_99_recall))
logger.info("Confusion Matrix for 99% Malicious Recall:")
logger.info(confusion_matrix(y_test_full, y_pred_99_recall))