"""
Sliding Window Analyzer for Network Traffic Data
Core analysis logic for window creation and aggregation
"""

import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Any
import warnings

from .config import WindowConfig

warnings.filterwarnings("ignore")


class SlidingWindowAnalyzer:
    """
    Analyzes network traffic data using sliding windows.
    Each row in the output represents one time window per group (e.g. IP).
    """

    def __init__(self, config: WindowConfig):
        self.config = config

    # ------------------------------------------------------------------
    # Column detection
    # ------------------------------------------------------------------
    def _auto_detect_columns(self, df: pd.DataFrame) -> tuple:
        """Automatically detect numeric and categorical columns"""

        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        categorical_cols = df.select_dtypes(include=["object", "category"]).columns.tolist()

        exclude = {self.config.timestamp_column, self.config.group_by_column}
        if self.config.label_column:
            exclude.add(self.config.label_column)

        numeric_cols = [c for c in numeric_cols if c not in exclude]
        categorical_cols = [c for c in categorical_cols if c not in exclude]

        return numeric_cols, categorical_cols

    # ------------------------------------------------------------------
    # Window creation
    # ------------------------------------------------------------------
    def _create_windows_for_group(
        self, group_df: pd.DataFrame, group_id: Any
    ) -> List[Dict]:

        windows = []
        if group_df.empty:
            return windows

        group_df = group_df.sort_values(self.config.timestamp_column).reset_index(drop=True)

        min_ts = group_df[self.config.timestamp_column].min()
        max_ts = group_df[self.config.timestamp_column].max()

        # Edge case: shorter than one window
        if (max_ts - min_ts) < self.config.window_size_seconds:
            window = self._aggregate_window(group_df, group_id, min_ts, max_ts)
            if window is not None:
                windows.append(window)
            return windows

        current_start = min_ts

        while current_start <= max_ts:
            current_end = current_start + self.config.window_size_seconds

            mask = (
                (group_df[self.config.timestamp_column] >= current_start)
                & (group_df[self.config.timestamp_column] < current_end)
            )
            window_df = group_df[mask]

            if not window_df.empty:
                window = self._aggregate_window(
                    window_df, group_id, current_start, current_end
                )
                if window is not None:
                    windows.append(window)

            current_start += self.config.step_size_seconds

        return windows

    # ------------------------------------------------------------------
    # Window aggregation
    # ------------------------------------------------------------------
    def _aggregate_window(
        self,
        window_df: pd.DataFrame,
        group_id: Any,
        start_ts: float,
        end_ts: float,
    ) -> Optional[Dict]:

        if window_df.empty:
            return None

        agg_data = {
            self.config.group_by_column: group_id,
            "window_start": start_ts,
            "window_end": end_ts,
            "window_duration": end_ts - start_ts,
            "n_connections": len(window_df),
        }

        # ----------------------------
        # Numeric aggregations
        # ----------------------------
        for col in self.config.numeric_columns:
            if col not in window_df.columns:
                continue

            values = window_df[col].dropna()
            for agg in self.config.numeric_aggregations:
                key = f"{col}_{agg}"
                if values.empty:
                    agg_data[key] = np.nan
                elif agg == "mean":
                    agg_data[key] = values.mean()
                elif agg == "std":
                    agg_data[key] = values.std()
                elif agg == "max":
                    agg_data[key] = values.max()

        # ----------------------------
        # Categorical aggregations
        # ----------------------------
        for col in self.config.categorical_columns:
            if col in window_df.columns:
                agg_data[f"{col}_nunique"] = window_df[col].nunique()

        # ----------------------------
        # Label aggregation
        # ----------------------------
        label = self.config.label_column
        if label and label in window_df.columns:
            labels = window_df[label].dropna().astype(int)

            if not labels.empty:
                total = len(labels)
                attack_count = labels.sum()
                ratio = attack_count / total

                # Store diagnostics
                agg_data[f"{label}_count"] = attack_count
                agg_data[f"{label}_ratio"] = ratio
                agg_data[f"{label}_any"] = int(attack_count > 0)
                agg_data[f"{label}_majority"] = int(attack_count > total / 2)

                # Final label decision
                if self.config.label_strategy == "majority":
                    agg_data[label] = agg_data[f"{label}_majority"]
                elif self.config.label_strategy == "any":
                    agg_data[label] = agg_data[f"{label}_any"]
                elif self.config.label_strategy == "threshold":
                    agg_data[label] = int(ratio >= self.config.label_threshold)
            else:
                agg_data[label] = 0

        return agg_data

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transform raw events into windowed features"""

        if self.config.numeric_columns is None or self.config.categorical_columns is None:
            num_cols, cat_cols = self._auto_detect_columns(df)
            self.config.numeric_columns = self.config.numeric_columns or num_cols
            self.config.categorical_columns = self.config.categorical_columns or cat_cols

        all_windows = []

        for group_id, group_df in df.groupby(self.config.group_by_column):
            windows = self._create_windows_for_group(group_df, group_id)
            all_windows.extend(windows)

        return pd.DataFrame(all_windows)

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Sklearn-like alias"""
        return self.transform(df)
