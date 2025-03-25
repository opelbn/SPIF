import xgboost as xgb
import numpy as np
print(f"XGBoost Version: {xgb.__version__}")

# Larger dummy dataset to ensure GPU kicks in
X_dummy = np.random.rand(10000, 10)
y_dummy = np.random.randint(0, 2, 10000)
d = xgb.DMatrix(X_dummy, label=y_dummy)
p = {'device': 'cuda', 'objective': 'binary:logistic'}

try:
    b = xgb.train(p, d, num_boost_round=5)
    print("CUDA worked! Training completed successfully.")
except xgb.core.XGBoostError as e:
    print(f"CUDA validation failed: {e}")