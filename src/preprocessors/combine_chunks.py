import numpy as np
import glob
import os

# Directory where chunks are saved
chunk_dir = "C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/"

# Find all X and y chunk files
x_chunks = sorted(glob.glob(os.path.join(chunk_dir, "X_chunk_*.npy")), key=lambda x: int(x.split("_")[-1].split(".")[0]))
y_chunks = sorted(glob.glob(os.path.join(chunk_dir, "y_chunk_*.npy")), key=lambda x: int(x.split("_")[-1].split(".")[0]))

# Combine X chunks
x_list = [np.load(chunk) for chunk in x_chunks]
X = np.vstack(x_list)
np.save("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/X.npy", X)

# Combine y chunks
y_list = [np.load(chunk) for chunk in y_chunks]
y = np.hstack(y_list)
np.save("C:/Users/benja/OneDrive/Documents/Projects/SNIF-L/src/preprocessors/y.npy", y)

print(f"Combined {len(x_chunks)} X chunks into X.npy with shape {X.shape}")
print(f"Combined {len(y_chunks)} y chunks into y.npy with shape {y.shape}")

# Verify distribution
print("Total samples:", len(y))
print("Benign (0):", np.sum(y == 0))
print("Malicious (1):", np.sum(y == 1))
print("Malicious percentage:", np.mean(y == 1) * 100)

# Clean up chunk files
for chunk in x_chunks + y_chunks:
    os.remove(chunk)
print("Cleaned up chunk files.")