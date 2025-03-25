import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tqdm import tqdm
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load the full preprocessed data
logger.info("Loading full preprocessed data...")
X_full = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/X.npy")
y_full = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/y.npy")
logger.info(f"Full data loaded: X shape {X_full.shape}, y shape {y_full.shape}")

# Create a balanced subsample for training
logger.info("Creating balanced subsample for training...")
benign_indices = np.where(y_full == 0)[0]
malicious_indices = np.where(y_full == 1)[0]

# Sample an equal number of benign and malicious samples
n_samples = len(benign_indices)  # Use all benign samples
np.random.seed(42)
malicious_sampled_indices = np.random.choice(malicious_indices, size=n_samples, replace=False)

# Combine indices
balanced_indices = np.concatenate([benign_indices, malicious_sampled_indices])
X_balanced = X_full[balanced_indices]
y_balanced = y_full[balanced_indices]
logger.info(f"Balanced subsample created: X shape {X_balanced.shape}, y shape {y_balanced.shape}")

# Split the full dataset into train and test (test set will be used for evaluation)
logger.info("Splitting full dataset into train/test sets...")
X_train_full, X_test_full, y_train_full, y_test_full = train_test_split(X_full, y_full, test_size=0.2, random_state=42)
logger.info(f"Full train set: {X_train_full.shape[0]} rows, Full test set: {X_test_full.shape[0]} rows")

logger.info("Saving test set for later evaluation...")
np.save("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/X_test.npy", X_test_full)
np.save("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/y_test.npy", y_test_full)

# Use the balanced subsample for training
X_train = X_balanced
y_train = y_balanced

# Create DMatrix for XGBoost
logger.info("Creating DMatrix...")
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test_full, label=y_test_full)
logger.info("DMatrix created")

# Define XGBoost parameters with CUDA
params = {
    'objective': 'binary:logistic',
    'max_depth': 6,
    'eta': 0.1,
    'eval_metric': 'logloss',
    'device': 'cuda',
    'nthread': -1
}

# No scale_pos_weight since training set is balanced
logger.info("Scale pos weight not applied (balanced training set)")

# Custom callback for progress reporting
class ProgressCallback(xgb.callback.TrainingCallback):
    def __init__(self, num_rounds):
        self.num_rounds = num_rounds
        self.pbar = tqdm(total=num_rounds, desc="Training Progress")

    def after_iteration(self, model, epoch, evals_log):
        self.pbar.update(1)
        if epoch == self.num_rounds - 1:
            self.pbar.close()
        if 'test' in evals_log and 'logloss' in evals_log['test']:
            logger.info(f"Epoch {epoch + 1}: Test Logloss = {evals_log['test']['logloss'][-1]:.6f}")
        return False

# Train the model with progress
num_rounds = 100
logger.info("Starting training with CUDA...")
bst = xgb.train(params, dtrain, num_rounds, evals=[(dtest, 'test')], 
                early_stopping_rounds=10, callbacks=[ProgressCallback(num_rounds)])

# Save the model
logger.info("Saving model...")
bst.save_model("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/models/xgboost_zeek_IoT_model_cuda_balanced.json")
logger.info("Model saved")

# Predict on the full test set
logger.info("Predicting on full test set...")
y_pred_proba = bst.predict(dtest)
y_pred = (y_pred_proba > 0.5).astype(int)  # Default threshold
logger.info("Predictions complete")

# Evaluate
logger.info("Classification Report:")
logger.info(classification_report(y_test_full, y_pred))
logger.info("Confusion Matrix:")
logger.info(confusion_matrix(y_test_full, y_pred))