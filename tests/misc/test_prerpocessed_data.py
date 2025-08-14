import numpy as np
y = np.load("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/y.npy")
print("Total samples:", len(y))
print("Benign (0):", np.sum(y == 0))
print("Malicious (1):", np.sum(y == 1))
print("Malicious percentage:", np.mean(y == 1) * 100)


