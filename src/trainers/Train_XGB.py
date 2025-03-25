import numpy as np
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from tqdm import tqdm
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load the preprocessed data
logger.info("Loading preprocessed data...")
X = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/X.npy")
y = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/y.npy")
logger.info(f"Data loaded: X shape {X.shape}, y shape {y.shape}")

# Split into training and testing sets with progress
logger.info("Splitting data into train/test sets...")
with tqdm(total=100, desc="Splitting Data") as pbar:
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    pbar.update(100)
logger.info(f"Train set: {X_train.shape[0]} rows, Test set: {X_test.shape[0]} rows")

# Create DMatrix for XGBoost
logger.info("Creating DMatrix...")
dtrain = xgb.DMatrix(X_train, label=y_train)
dtest = xgb.DMatrix(X_test, label=y_test)
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

# Add scale_pos_weight to handle imbalance
params['scale_pos_weight'] = (np.sum(y_train == 0) / np.sum(y_train == 1)) * 2  # Double the weight
logger.info(f"Scale pos weight: {params['scale_pos_weight']}")

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
bst.save_model("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/models/xgboost_zeek_IoT_model_cuda.json")
logger.info("Model saved")

# Predict on test set with adjusted threshold
logger.info("Predicting on test set...")
y_pred_proba = bst.predict(dtest)
y_pred = (y_pred_proba > 0.3).astype(int)  # Lower threshold to 0.3
logger.info("Predictions complete")

# Evaluate
logger.info("Classification Report:")
logger.info(classification_report(y_test, y_pred))
logger.info("Confusion Matrix:")
logger.info(confusion_matrix(y_test, y_pred))