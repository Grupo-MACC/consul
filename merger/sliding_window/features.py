"""
Feature engineering functions for Consul poisoning detection
Custom features can be applied optionally after window aggregation
"""

import pandas as pd
import numpy as np


def create_consul_poisoning_features(window_df: pd.DataFrame) -> pd.DataFrame:
    """
    Feature engineering specifically for Consul poisoning detection.
    This function is provided for custom use but not applied by default.
    
    Consul poisoning characteristics:
    - Reconnaissance: scanning multiple services/ports
    - Registration: sudden appearance as new service
    - Traffic redirection: receiving traffic meant for legitimate services
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Windowed data from SlidingWindowAnalyzer
        
    Returns:
    --------
    pd.DataFrame
        Input dataframe with additional engineered features
    """
    
    df = window_df.copy()
    
    # Reconnaissance patterns
    if 'id.resp_p_nunique' in df.columns:
        # High port scanning indicator
        df['port_scan_intensity'] = df['id.resp_p_nunique'] / df['n_connections']
    
    if 'service_nunique' in df.columns:
        # Service diversity indicator
        df['service_diversity'] = df['service_nunique'] / df['n_connections']
    
    # Traffic volume anomalies
    if 'orig_bytes_mean' in df.columns and 'resp_bytes_mean' in df.columns:
        # Asymmetric traffic (potential data exfiltration)
        df['traffic_asymmetry'] = np.abs(df['orig_bytes_mean'] - df['resp_bytes_mean']) / \
                                   (df['orig_bytes_mean'] + df['resp_bytes_mean'] + 1e-6)
    
    if 'orig_bytes_std' in df.columns:
        # Traffic variability
        df['traffic_variability'] = df['orig_bytes_std'] / (df['orig_bytes_mean'] + 1e-6)
    
    # Connection patterns
    if 'duration_mean' in df.columns and 'duration_std' in df.columns:
        # Connection duration consistency
        df['duration_consistency'] = df['duration_std'] / (df['duration_mean'] + 1e-6)
    
    if 'conn_state_nunique' in df.columns:
        # Connection state diversity (failed connections, etc.)
        df['conn_state_diversity'] = df['conn_state_nunique'] / df['n_connections']
    
    # Temporal patterns
    if 'conn_interval_mean' in df.columns and 'conn_interval_std' in df.columns:
        # Regular/scripted behavior indicator
        df['temporal_regularity'] = df['conn_interval_std'] / (df['conn_interval_mean'] + 1e-6)
    
    # Burst activity
    if 'burst_score_max' in df.columns:
        df['burst_intensity'] = df['burst_score_max']
    
    # Reconnaissance scores
    if 'recon_pattern_score_mean' in df.columns:
        df['recon_score_mean'] = df['recon_pattern_score_mean']
    
    # JA3 fingerprint anomalies
    if 'ja3_frequency_mean' in df.columns:
        # Low frequency JA3 might indicate custom/malicious clients
        df['rare_ja3_indicator'] = (df['ja3_frequency_mean'] < 10).astype(int)
    
    if 'unique_ja3_from_ip_mean' in df.columns:
        # Multiple JA3s from same IP might indicate tool switching
        df['ja3_switching'] = df['unique_ja3_from_ip_mean'] > 1.5
    
    return df


def create_temporal_features(window_df: pd.DataFrame) -> pd.DataFrame:
    """
    Create temporal features based on window timestamps
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Windowed data with window_start and window_end columns
        
    Returns:
    --------
    pd.DataFrame
        Input dataframe with additional temporal features
    """
    
    df = window_df.copy()
    
    if 'window_start' in df.columns:
        # Convert to datetime for easier manipulation
        df['window_start_dt'] = pd.to_datetime(df['window_start'], unit='s')
        
        # Extract time-based features
        # DO NOT USE FOR TRAINING
        df['hour_of_day'] = df['window_start_dt'].dt.hour
        df['day_of_week'] = df['window_start_dt'].dt.dayofweek
        df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
        df['is_business_hours'] = ((df['hour_of_day'] >= 9) & (df['hour_of_day'] <= 17)).astype(int)
        
    return df

# Might be data leakage if used improperly
def create_ip_profile_features(window_df: pd.DataFrame) -> pd.DataFrame:
    """
    Create features based on IP behavior profiles across all windows
    
    Parameters:
    -----------
    window_df : pd.DataFrame
        Windowed data grouped by IP
        
    Returns:
    --------
    pd.DataFrame
        Input dataframe with IP profile features
    """
    
    df = window_df.copy()
    
    if 'id.orig_h' in df.columns:
        # Calculate IP-level statistics
        ip_stats = df.groupby('id.orig_h').agg({
            'n_connections': ['sum', 'mean', 'std'],
            'window_start': 'count'  # number of windows per IP
        })
        
        ip_stats.columns = ['_'.join(col).strip() for col in ip_stats.columns.values]
        ip_stats = ip_stats.rename(columns={'window_start_count': 'total_windows'})
        ip_stats = ip_stats.reset_index()
        
        # Merge back to original dataframe
        df = df.merge(ip_stats, on='id.orig_h', how='left', suffixes=('', '_ip_profile'))
        
        # Create relative features
        if 'n_connections' in df.columns and 'n_connections_mean' in df.columns:
            df['conn_deviation_from_ip_avg'] = (df['n_connections'] - df['n_connections_mean']) / \
                                                (df['n_connections_std'] + 1e-6)
    
    return df