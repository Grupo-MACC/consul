"""
Utility functions for window analysis and data exploration
"""

import pandas as pd
from typing import Dict


def analyze_windows(window_df: pd.DataFrame, output_stats: bool = True) -> Dict:
    """
    Analyze the windowed data and provide summary statistics.
    Useful for understanding data distribution before clustering.
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Output from SlidingWindowAnalyzer
    output_stats : bool
        Whether to print statistics
        
    Returns:
    --------
    Dict
        Dictionary with analysis results
    """
    
    stats = {
        'total_windows': len(window_df),
        'unique_ips': window_df['id.orig_h'].nunique() if 'id.orig_h' in window_df.columns else None,
        'avg_connections_per_window': window_df['n_connections'].mean() if 'n_connections' in window_df.columns else None,
        'windows_per_ip': len(window_df) / window_df['id.orig_h'].nunique() if 'id.orig_h' in window_df.columns else None,
    }
    
    # Attack distribution (if labels exist)
    if 'is_attack' in window_df.columns:
        stats['attack_windows'] = window_df['is_attack'].sum()
        stats['normal_windows'] = len(window_df) - stats['attack_windows']
        stats['attack_ratio'] = stats['attack_windows'] / len(window_df)
    
    if output_stats:
        print("=" * 60)
        print("WINDOWED DATA ANALYSIS")
        print("=" * 60)
        for key, value in stats.items():
            if isinstance(value, float):
                print(f"{key}: {value:.4f}")
            else:
                print(f"{key}: {value}")
        print("=" * 60)
    
    return stats


def export_windows(window_df: pd.DataFrame, filepath: str, format: str = 'csv'):
    """
    Export windowed data to file
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Windowed data to export
    filepath : str
        Path where to save the file
    format : str
        Format to use: 'csv', 'parquet', or 'pickle'
    """
    
    if format == 'csv':
        window_df.to_csv(filepath, index=False)
    elif format == 'parquet':
        window_df.to_parquet(filepath, index=False)
    elif format == 'pickle':
        window_df.to_pickle(filepath)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'csv', 'parquet', or 'pickle'")
    
    print(f"Exported {len(window_df)} windows to {filepath}")


def load_windows(filepath: str, format: str = 'csv') -> pd.DataFrame:
    """
    Load windowed data from file
    
    Parameters:
    -----------
    filepath : str
        Path to the file
    format : str
        Format of the file: 'csv', 'parquet', or 'pickle'
        
    Returns:
    --------
    pd.DataFrame
        Loaded windowed data
    """
    
    if format == 'csv':
        df = pd.read_csv(filepath)
    elif format == 'parquet':
        df = pd.read_parquet(filepath)
    elif format == 'pickle':
        df = pd.read_pickle(filepath)
    else:
        raise ValueError(f"Unsupported format: {format}. Use 'csv', 'parquet', or 'pickle'")
    
    print(f"Loaded {len(df)} windows from {filepath}")
    return df


def get_windows_by_ip(window_df: pd.DataFrame, ip_address: str) -> pd.DataFrame:
    """
    Extract all windows for a specific IP address
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Windowed data
    ip_address : str
        IP address to filter
        
    Returns:
    --------
    pd.DataFrame
        Windows for the specified IP
    """
    
    if 'id.orig_h' not in window_df.columns:
        raise ValueError("Column 'id.orig_h' not found in dataframe")
    
    filtered = window_df[window_df['id.orig_h'] == ip_address].copy()
    filtered = filtered.sort_values('window_start')
    
    print(f"Found {len(filtered)} windows for IP {ip_address}")
    return filtered


def visualize_window_distribution(window_df: pd.DataFrame):
    """
    Create basic visualizations of window distribution
    Requires matplotlib and seaborn
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Windowed data to visualize
    """
    
    try:
        import matplotlib.pyplot as plt
        import seaborn as sns
    except ImportError:
        print("matplotlib and seaborn required for visualization")
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    
    # Connections per window
    axes[0, 0].hist(window_df['n_connections'], bins=50, edgecolor='black')
    axes[0, 0].set_xlabel('Connections per Window')
    axes[0, 0].set_ylabel('Frequency')
    axes[0, 0].set_title('Distribution of Connections per Window')
    
    # Windows per IP
    if 'id.orig_h' in window_df.columns:
        windows_per_ip = window_df['id.orig_h'].value_counts()
        axes[0, 1].hist(windows_per_ip, bins=50, edgecolor='black')
        axes[0, 1].set_xlabel('Windows per IP')
        axes[0, 1].set_ylabel('Frequency')
        axes[0, 1].set_title('Distribution of Windows per IP')
    
    # Attack distribution (if available)
    if 'is_attack' in window_df.columns:
        attack_counts = window_df['is_attack'].value_counts()
        axes[1, 0].bar(['Normal', 'Attack'], attack_counts.values)
        axes[1, 0].set_ylabel('Count')
        axes[1, 0].set_title('Attack vs Normal Windows')
    
    # Window duration
    axes[1, 1].hist(window_df['window_duration'], bins=50, edgecolor='black')
    axes[1, 1].set_xlabel('Window Duration (seconds)')
    axes[1, 1].set_ylabel('Frequency')
    axes[1, 1].set_title('Distribution of Window Durations')
    
    plt.tight_layout()
    plt.show()