"""
Diagnostic utilities to understand label distribution changes
after windowing transformation
"""

import pandas as pd
import numpy as np
from typing import Optional
import matplotlib.pyplot as plt
import seaborn as sns


def diagnose_label_distribution(original_df: pd.DataFrame, 
                                windowed_df: pd.DataFrame,
                                label_col: str = 'is_attack',
                                timestamp_col: str = 'ts',
                                group_col: str = 'id.orig_h') -> dict:
    """
    Diagnose why label distribution changes after windowing.
    
    Parameters:
    -----------
    original_df : pd.DataFrame
        Original dataset before windowing
    windowed_df : pd.DataFrame
        After windowing transformation
    label_col : str
        Name of label column
    timestamp_col : str
        Name of timestamp column
    group_col : str
        Name of grouping column (typically IP)
        
    Returns:
    --------
    dict : Diagnostic information
    """
    
    print("=" * 70)
    print("LABEL DISTRIBUTION DIAGNOSIS")
    print("=" * 70)
    
    # Original distribution
    orig_total = len(original_df)
    orig_attacks = original_df[label_col].sum()
    orig_ratio = orig_attacks / orig_total
    
    print(f"\n📊 ORIGINAL DATASET:")
    print(f"  Total connections: {orig_total:,}")
    print(f"  Attack connections: {orig_attacks:,} ({orig_ratio*100:.1f}%)")
    print(f"  Normal connections: {orig_total - orig_attacks:,} ({(1-orig_ratio)*100:.1f}%)")
    
    # Windowed distribution (multiple strategies)
    win_total = len(windowed_df)
    
    print(f"\n📊 WINDOWED DATASET:")
    print(f"  Total windows: {win_total:,}")
    
    if f'{label_col}_majority' in windowed_df.columns:
        win_attacks_maj = windowed_df[f'{label_col}_majority'].sum()
        print(f"  Attack windows (majority): {win_attacks_maj:,} ({win_attacks_maj/win_total*100:.1f}%)")
    
    if f'{label_col}_any' in windowed_df.columns:
        win_attacks_any = windowed_df[f'{label_col}_any'].sum()
        print(f"  Attack windows (any): {win_attacks_any:,} ({win_attacks_any/win_total*100:.1f}%)")
    
    if f'{label_col}_ratio' in windowed_df.columns:
        avg_ratio = windowed_df[f'{label_col}_ratio'].mean()
        print(f"  Avg attack ratio per window: {avg_ratio*100:.1f}%")
    
    # Temporal analysis
    print(f"\n⏱️  TEMPORAL ANALYSIS:")
    
    # Group by IP and analyze
    ip_stats = []
    for ip in original_df[group_col].unique():
        ip_data = original_df[original_df[group_col] == ip].sort_values(timestamp_col)
        
        if len(ip_data) == 0:
            continue
            
        duration = ip_data[timestamp_col].max() - ip_data[timestamp_col].min()
        attack_ratio = ip_data[label_col].mean()
        
        # Check if attacks are concentrated
        ip_data['time_bucket'] = pd.cut(ip_data[timestamp_col], bins=min(10, len(ip_data)))
        attacks_by_bucket = ip_data.groupby('time_bucket')[label_col].sum()
        attack_concentration = attacks_by_bucket.max() / (attacks_by_bucket.sum() + 1e-6)
        
        ip_stats.append({
            'ip': ip,
            'total_conns': len(ip_data),
            'attack_ratio': attack_ratio,
            'duration': duration,
            'attack_concentration': attack_concentration
        })
    
    ip_df = pd.DataFrame(ip_stats)
    
    print(f"  Total unique IPs: {len(ip_df)}")
    print(f"  Avg connections per IP: {ip_df['total_conns'].mean():.1f}")
    print(f"  Avg duration per IP: {ip_df['duration'].mean():.1f}s")
    print(f"  IPs with >50% attacks: {(ip_df['attack_ratio'] > 0.5).sum()}")
    print(f"  IPs with concentrated attacks: {(ip_df['attack_concentration'] > 0.7).sum()}")
    
    # Analyze mixed windows
    if f'{label_col}_any' in windowed_df.columns and f'{label_col}_majority' in windowed_df.columns:
        mixed_windows = windowed_df[
            (windowed_df[f'{label_col}_any'] == 1) & 
            (windowed_df[f'{label_col}_majority'] == 0)
        ]
        print(f"\n⚠️  MIXED WINDOWS (have attacks but not majority):")
        print(f"  Count: {len(mixed_windows):,} ({len(mixed_windows)/win_total*100:.1f}%)")
        
        if len(mixed_windows) > 0 and f'{label_col}_ratio' in windowed_df.columns:
            print(f"  Avg attack ratio in mixed: {mixed_windows[f'{label_col}_ratio'].mean()*100:.1f}%")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    
    if orig_ratio > 0.5 and f'{label_col}_majority' in windowed_df.columns:
        win_ratio_maj = windowed_df[f'{label_col}_majority'].mean()
        if win_ratio_maj < 0.4:
            print("  ⚠️  Large drop in attack ratio detected!")
            print("  → Attacks appear to be temporally concentrated")
            print("  → Consider using 'label_strategy=any' in WindowConfig")
            print("  → Or use smaller window_size to capture attack bursts")
    
    high_concentration = (ip_df['attack_concentration'] > 0.7).mean()
    if high_concentration > 0.3:
        print(f"  ⚠️  {high_concentration*100:.0f}% of IPs have concentrated attacks")
        print("  → Try smaller window_size (e.g., 10-15s instead of 30s)")
        print("  → Or use step_size = window_size (non-overlapping windows)")
    
    return {
        'original_attack_ratio': orig_ratio,
        'windowed_attack_ratio_majority': windowed_df[f'{label_col}_majority'].mean() if f'{label_col}_majority' in windowed_df.columns else None,
        'windowed_attack_ratio_any': windowed_df[f'{label_col}_any'].mean() if f'{label_col}_any' in windowed_df.columns else None,
        'ip_stats': ip_df
    }


def plot_temporal_attack_distribution(df: pd.DataFrame, 
                                      label_col: str = 'is_attack',
                                      timestamp_col: str = 'ts',
                                      group_col: str = 'id.orig_h',
                                      n_ips: int = 5):
    """
    Visualize how attacks are distributed over time for different IPs.
    
    Parameters:
    -----------
    df : pd.DataFrame
        Original dataset
    label_col : str
        Label column name
    timestamp_col : str
        Timestamp column name
    group_col : str
        Grouping column (IP)
    n_ips : int
        Number of IPs to visualize
    """
    
    fig, axes = plt.subplots(n_ips, 1, figsize=(15, 3*n_ips))
    if n_ips == 1:
        axes = [axes]
    
    # Get IPs with most connections
    top_ips = df[group_col].value_counts().head(n_ips).index
    
    for idx, ip in enumerate(top_ips):
        ip_data = df[df[group_col] == ip].sort_values(timestamp_col).reset_index(drop=True)
        
        # Normalize timestamps to start at 0
        ip_data['time_relative'] = ip_data[timestamp_col] - ip_data[timestamp_col].min()
        
        # Create timeline
        attacks = ip_data[ip_data[label_col] == 1]['time_relative']
        normals = ip_data[ip_data[label_col] == 0]['time_relative']
        
        axes[idx].scatter(attacks, [1]*len(attacks), c='red', alpha=0.6, s=50, label='Attack')
        axes[idx].scatter(normals, [0]*len(normals), c='blue', alpha=0.3, s=50, label='Normal')
        
        axes[idx].set_ylabel(f'{ip}\n(n={len(ip_data)})')
        axes[idx].set_ylim(-0.5, 1.5)
        axes[idx].set_yticks([0, 1])
        axes[idx].set_yticklabels(['Normal', 'Attack'])
        axes[idx].legend(loc='upper right')
        axes[idx].grid(True, alpha=0.3)
        
        if idx == n_ips - 1:
            axes[idx].set_xlabel('Time (seconds from first connection)')
    
    plt.suptitle('Temporal Distribution of Attacks by IP', fontsize=14, fontweight='bold')
    plt.tight_layout()
    plt.show()


def compare_labeling_strategies(windowed_df: pd.DataFrame,
                                label_col: str = 'is_attack',
                                thresholds: list = [0.1, 0.3, 0.5, 0.7]):
    """
    Compare different labeling strategies on windowed data.
    
    Parameters:
    -----------
    windowed_df : pd.DataFrame
        Windowed dataset
    label_col : str
        Label column name
    thresholds : list
        Thresholds to test for ratio-based labeling
    """
    
    print("=" * 70)
    print("LABELING STRATEGY COMPARISON")
    print("=" * 70)
    
    total = len(windowed_df)
    
    strategies = {}
    
    # Majority
    if f'{label_col}_majority' in windowed_df.columns:
        strategies['majority'] = windowed_df[f'{label_col}_majority'].sum()
    
    # Any
    if f'{label_col}_any' in windowed_df.columns:
        strategies['any'] = windowed_df[f'{label_col}_any'].sum()
    
    # Thresholds
    if f'{label_col}_ratio' in windowed_df.columns:
        for thresh in thresholds:
            count = (windowed_df[f'{label_col}_ratio'] >= thresh).sum()
            strategies[f'threshold_{thresh}'] = count
    
    print(f"\nTotal windows: {total:,}\n")
    print(f"{'Strategy':<20} {'Attack Windows':<15} {'Percentage':<15}")
    print("-" * 50)
    
    for strategy, count in sorted(strategies.items(), key=lambda x: x[1], reverse=True):
        pct = count / total * 100
        print(f"{strategy:<20} {count:<15,} {pct:<15.1f}%")
    
    # Visualization
    if len(strategies) > 0:
        fig, ax = plt.subplots(figsize=(12, 6))
        
        names = list(strategies.keys())
        values = list(strategies.values())
        percentages = [v/total*100 for v in values]
        
        bars = ax.bar(names, percentages, color=['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#ffeaa7'])
        
        # Add value labels on bars
        for bar, val, pct in zip(bars, values, percentages):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{val:,}\n({pct:.1f}%)',
                   ha='center', va='bottom', fontsize=9)
        
        ax.set_ylabel('Percentage of Attack Windows', fontsize=12)
        ax.set_xlabel('Labeling Strategy', fontsize=12)
        ax.set_title('Attack Detection Rate by Labeling Strategy', fontsize=14, fontweight='bold')
        ax.grid(axis='y', alpha=0.3)
        
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.show()