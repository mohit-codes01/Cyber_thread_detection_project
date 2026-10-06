import pandas as pd
import joblib

from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix


# ==========================================
# 1. LOAD DATASET
# ==========================================

train_path = "data/UNSW_NB15_training-set.csv"
test_path = "data/UNSW_NB15_testing-set.csv"

print("Loading dataset...")

train_df = pd.read_csv(train_path)
test_df = pd.read_csv(test_path)

print("Training data:", train_df.shape)
print("Testing data :", test_df.shape)


# ==========================================
# 2. CLEANING
# ==========================================

print("\nCleaning dataset...")

# Remove unnecessary columns
drop_columns = ["id", "attack_cat"]

for col in drop_columns:
    if col in train_df.columns:
        train_df = train_df.drop(columns=[col])

    if col in test_df.columns:
        test_df = test_df.drop(columns=[col])


# ==========================================
# 3. FEATURES AND TARGET
# ==========================================

X_train = train_df.drop(columns=["label"])
y_train = train_df["label"]

X_test = test_df.drop(columns=["label"])
y_test = test_df["label"]

print("\nNumber of features:", X_train.shape[1])
print("Target: label")


# ==========================================
# 4. IDENTIFY CATEGORICAL & NUMERICAL FEATURES
# ==========================================

categorical_features = X_train.select_dtypes(
    include=["object"]
).columns.tolist()

numerical_features = X_train.select_dtypes(
    exclude=["object"]
).columns.tolist()

print("\nCategorical features:")
print(categorical_features)

print("\nNumerical features:")
print(numerical_features)


# ==========================================
# 5. DATA PREPROCESSING
# ==========================================

numeric_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="median"))
])

categorical_pipeline = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("encoder", OneHotEncoder(handle_unknown="ignore", sparse_output=True))
])

preprocessor = ColumnTransformer([
    ("numeric", numeric_pipeline, numerical_features),
    ("categorical", categorical_pipeline, categorical_features)
])


# ==========================================
# 6. MACHINE LEARNING MODEL
# ==========================================

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)


# ==========================================
# 7. COMPLETE ML PIPELINE
# ==========================================

pipeline = Pipeline([
    ("preprocessing", preprocessor),
    ("model", model)
])


# ==========================================
# 8. TRAIN MODEL
# ==========================================

print("\nTraining Random Forest model...")
print("Please wait...")

pipeline.fit(X_train, y_train)

print("Model training completed!")


# ==========================================
# 9. TEST MODEL
# ==========================================

print("\nTesting model...")

y_pred = pipeline.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n================================")
print("MODEL ACCURACY:", accuracy)
print("================================")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# ==========================================
# 10. SAVE MODEL
# ==========================================

model_path = "models/threat_model.pkl"

# Save with compression (keeps size ~18.5 MB, well under GitHub 100MB limit)
joblib.dump(pipeline, model_path, compress=7)

print("\nModel saved successfully!")
print("Saved at:", model_path)

print("\nCyber Threat Detection ML pipeline completed!")