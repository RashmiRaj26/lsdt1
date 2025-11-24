# Agglomerative Clustering

# --------------------------------------------
# 1. Import Libraries
# --------------------------------------------
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.cluster import AgglomerativeClustering
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import (
    silhouette_score,
    davies_bouldin_score,
    calinski_harabasz_score
)

# --------------------------------------------
# 2. Load Dataset
# --------------------------------------------
df = pd.read_csv("node_metrics.csv")   # <-- replace with your file name

# Use only numeric columns
df_numeric = df.select_dtypes(include=np.number).dropna()
X = df_numeric.values

# --------------------------------------------
# 3. Train-Test Split + Scaling
# --------------------------------------------
X_train, X_test = train_test_split(X, test_size=0.3, random_state=42)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# --------------------------------------------
# 4. Agglomerative Clustering
# --------------------------------------------
# We choose 2 clusters (Malicious vs Not Malicious)
model = AgglomerativeClustering(n_clusters=2, linkage='ward')
train_clusters = model.fit_predict(X_train_scaled)

# Predict for test data manually (hierarchical clustering cannot predict)
# → assign test points to nearest cluster centroid
centroids = []

for c in [0, 1]:
    centroids.append(X_train_scaled[train_clusters == c].mean(axis=0))

centroids = np.array(centroids)

from scipy.spatial.distance import cdist
test_clusters = np.argmin(cdist(X_test_scaled, centroids), axis=1)

# --------------------------------------------
# 5. Evaluation Metrics
# --------------------------------------------
silhouette = silhouette_score(X_train_scaled, train_clusters)
dbi = davies_bouldin_score(X_train_scaled, train_clusters)
ch = calinski_harabasz_score(X_train_scaled, train_clusters)

print("------ PERFORMANCE ------")
print(f"Silhouette Score: {silhouette:.4f}  (higher = better)")
print(f"Davies–Bouldin Index: {dbi:.4f}  (lower = better)")
print(f"Calinski–Harabasz Score: {ch:.4f}  (higher = better)")

# --------------------------------------------
# 6. Rename Clusters
# --------------------------------------------
labels_train_named = np.where(train_clusters == 1, "Malicious", "Not Malicious")
labels_test_named  = np.where(test_clusters == 1, "Malicious", "Not Malicious")

# --------------------------------------------
# 7. Visualization (PCA 2D)
# --------------------------------------------
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_train_scaled)

colors = np.where(train_clusters == 1, "red", "green")

plt.figure(figsize=(8,6))
plt.scatter(X_pca[:,0], X_pca[:,1], c=colors, alpha=0.7)

# Legend
import matplotlib.patches as mpatches
red_patch = mpatches.Patch(color='red', label='Malicious')
green_patch = mpatches.Patch(color='green', label='Not Malicious')
plt.legend(handles=[red_patch, green_patch])

plt.title("Agglomerative Clustering (PCA Visualization)")
plt.xlabel("PCA Component 1")
plt.ylabel("PCA Component 2")
plt.grid(True)
plt.show()
