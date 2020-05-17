import json
import numpy as np
import pandas as pd
from sklearn.neighbors import KNeighborsClassifier
from sklearn import preprocessing as prep
import sys

train_data = sys.argv[1]
lables_file = sys.argv[2]
data_file = sys.argv[3]

with open(train_data) as f:
    X = json.load(f)

with open(lables_file) as f:
    Y = json.load(f)

with open(data_file) as f:
    data = json.load(f)

neigh = KNeighborsClassifier(n_neighbors=5)

neigh.fit(X, Y)

print(neigh.predict(data))