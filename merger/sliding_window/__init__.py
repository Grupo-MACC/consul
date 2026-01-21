"""
Sliding Window Analyzer Package
================================

A modular package for analyzing network traffic data using sliding windows,
designed specifically for Consul poisoning attack detection using 
unsupervised/semi-supervised learning approaches.

Main Components:
---------------
- WindowConfig: Configuration class for window parameters
- SlidingWindowAnalyzer: Core analyzer for creating sliding windows
- Feature engineering functions: Custom features for attack detection
- Utility functions: Analysis, export, and visualization tools

Example Usage:
-------------
    from sliding_window import SlidingWindowAnalyzer, WindowConfig
    from sliding_window import create_consul_poisoning_features
    
    # Configure
    config = WindowConfig(
        window_size_seconds=30.0,
        step_size_seconds=5.0
    )
    
    # Analyze
    analyzer = SlidingWindowAnalyzer(config)
    windowed_df = analyzer.transform(df)
    
    # Optional: Add custom features
    windowed_df = create_consul_poisoning_features(windowed_df)
"""

from .config import WindowConfig
from .analyzer import SlidingWindowAnalyzer
from .features import (
    create_consul_poisoning_features,
    create_temporal_features,
    create_ip_profile_features
)
from .utils import (
    analyze_windows,
    export_windows,
    load_windows,
    get_windows_by_ip,
    visualize_window_distribution
)
from .diagnostics import (
    diagnose_label_distribution,
    plot_temporal_attack_distribution,
    compare_labeling_strategies
)
from .window_parameter_optimizer import (
    optimize_window_parameters,
    OptimizationResult
)


__version__ = '1.0.0'
__author__ = 'Network Security Analysis'

__all__ = [
    'WindowConfig',
    'SlidingWindowAnalyzer',
    'create_consul_poisoning_features',
    'create_temporal_features',
    'create_ip_profile_features',
    'analyze_windows',
    'export_windows',
    'load_windows',
    'get_windows_by_ip',
    'visualize_window_distribution',
    'diagnose_label_distribution',
    'plot_temporal_attack_distribution',
    'compare_labeling_strategies',
    'optimize_window_parameters',
    'OptimizationResult'
]