"""
Configuration classes for sliding window analysis
"""

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class WindowConfig:
    """Configuration for sliding window analysis"""
    window_size_seconds: float = 30.0
    step_size_seconds: float = 5.0
    group_by_column: str = 'id.orig_h'
    timestamp_column: str = 'ts'
    label_column: Optional[str] = 'is_attack'
    
    # Columns to aggregate with different strategies
    numeric_columns: Optional[List[str]] = None
    categorical_columns: Optional[List[str]] = None
    
    # Aggregation functions for numeric columns
    numeric_aggregations: List[str] = None
    
    # Label aggregation strategy
    label_strategy: str = 'any'  # 'majority', 'any', 'threshold'
    label_threshold: float = 0.3  # For 'threshold' strategy: ratio to consider attack
    
    def __post_init__(self):
        if self.numeric_aggregations is None:
            self.numeric_aggregations = ['mean', 'std', 'max']
        
        if self.label_strategy not in ['majority', 'any', 'threshold']:
            raise ValueError("label_strategy must be 'majority', 'any', or 'threshold'")