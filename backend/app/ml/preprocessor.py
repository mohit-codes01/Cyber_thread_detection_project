"""
Machine Learning Preprocessing Pipeline
Handles automated feature extraction, imputation, scaling, and categorical encoding.
"""

from typing import List, Tuple, Dict, Any
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer


class MLPreprocessor:
    """Prepares generic and security-specific datasets for machine learning."""

    def __init__(self, max_categories: int = 20):
        self.max_categories = max_categories
        self.transformer: ColumnTransformer = None
        self.feature_names: List[str] = []
        self.numeric_cols: List[str] = []
        self.categorical_cols: List[str] = []

    def fit_transform(self, df: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """Identifies numeric and categorical features and fits transformers."""
        # Drop high-cardinality or raw text columns
        clean_df = df.copy()
        drop_cols = []
        for col in clean_df.columns:
            # Drop identifiers and freeform timestamps
            col_lower = col.lower()
            if col_lower in ['id', 'raw_data', 'raw_log', 'user_agent', 'url', 'evidence', 'explanation']:
                drop_cols.append(col)
            elif clean_df[col].nunique() == len(clean_df) and clean_df[col].dtype == 'object':
                drop_cols.append(col)
        
        clean_df = clean_df.drop(columns=drop_cols, errors='ignore')

        self.numeric_cols = clean_df.select_dtypes(include=[np.number]).columns.tolist()
        self.categorical_cols = clean_df.select_dtypes(include=['object', 'category', 'bool']).columns.tolist()

        # Filter categorical columns to manageable cardinality
        self.categorical_cols = [
            c for c in self.categorical_cols if clean_df[c].nunique() <= self.max_categories
        ]

        transformers = []
        if self.numeric_cols:
            num_pipe = Pipeline([
                ('imputer', SimpleImputer(strategy='median')),
                ('scaler', StandardScaler())
            ])
            transformers.append(('num', num_pipe, self.numeric_cols))

        if self.categorical_cols:
            cat_pipe = Pipeline([
                ('imputer', SimpleImputer(strategy='most_frequent')),
                ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
            ])
            transformers.append(('cat', cat_pipe, self.categorical_cols))

        if not transformers:
            # Edge case: no valid columns found, create dummy column
            dummy = np.zeros((len(df), 1))
            return dummy, ["dummy_feature"]

        self.transformer = ColumnTransformer(transformers=transformers)
        transformed_matrix = self.transformer.fit_transform(clean_df)

        # Derive feature names
        feature_names = []
        if self.numeric_cols:
            feature_names.extend(self.numeric_cols)
        if self.categorical_cols:
            try:
                cat_encoder = self.transformer.named_transformers_['cat'].named_steps['onehot']
                cat_names = cat_encoder.get_feature_names_out(self.categorical_cols)
                feature_names.extend(list(cat_names))
            except Exception:
                feature_names.extend(self.categorical_cols)

        self.feature_names = feature_names
        return transformed_matrix, feature_names
