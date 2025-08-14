import xgboost as xgb
print(xgb.__version__)
d = xgb.DMatrix([[1]], label=[0])
p = {'device': 'cuda'}
b = xgb.train(p, d, 1)
print("CUDA worked!")