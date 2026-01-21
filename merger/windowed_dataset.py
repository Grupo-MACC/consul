"""
Windowed Dataset Exporter for ADS
==================================

Converts windowed Zeek logs to dataset format for ML model training.
Uses sliding window analysis to create temporal windows of network traffic.
"""

import pandas as pd
import numpy as np
from pathlib import Path
from typing import Optional, Tuple
import logging
from datetime import datetime

from sliding_window import (
    SlidingWindowAnalyzer,
    WindowConfig,
    analyze_windows,
    export_windows
)

logger = logging.getLogger(__name__)


class WindowedDatasetGenerator:
    """Generate windowed datasets from Zeek logs"""
    
    def __init__(
        self,
        zeek_logs_dir: str = "/zeek_logs",
        window_size_seconds: float = 30.0,
        step_size_seconds: float = 5.0
    ):
        self.zeek_logs_dir = Path(zeek_logs_dir)
        self.window_config = WindowConfig(
            window_size_seconds=window_size_seconds,
            step_size_seconds=step_size_seconds,
            group_by_column='id.orig_h',
            timestamp_column='ts',
            label_column=None,  # No automatic labeling
        )
        self.analyzer = SlidingWindowAnalyzer(self.window_config)
    
    def load_zeek_conn_logs(self) -> pd.DataFrame:
        """
        Load all conn.log files from Zeek logs directory
        
        Returns:
        --------
        pd.DataFrame
            Combined connection logs from all files
        """
        
        conn_files = list(self.zeek_logs_dir.glob("conn.log*"))
        
        if not conn_files:
            logger.warning(f"No conn.log files found in {self.zeek_logs_dir}")
            return pd.DataFrame()
        
        dfs = []
        for conn_file in sorted(conn_files):
            try:
                # Read Zeek TSV file with header parsing
                df = self._read_zeek_tsv(conn_file)
                
                if not df.empty and len(df.columns) > 5:  # Ensure we have data columns
                    dfs.append(df)
                    logger.info(f"Loaded {len(df)} connections from {conn_file.name}")
                elif df.empty:
                    logger.debug(f"Skipped empty file: {conn_file.name}")
            except Exception as e:
                logger.warning(f"Error reading {conn_file.name}: {e}")
        
        if not dfs:
            logger.error("No valid connection data loaded")
            return pd.DataFrame()
        
        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Total connections loaded: {len(df)}")
        
        return df
    
    def _read_zeek_tsv(self, filepath) -> pd.DataFrame:
        """
        Read Zeek TSV file with proper header handling
        
        Zeek TSV files have metadata lines starting with # followed by data
        """
        fields = None
        
        # Parse the header to find field names
        with open(filepath, 'r') as f:
            for line in f:
                if line.startswith('#fields\t'):
                    # Extract field names from #fields line
                    fields = line[8:].strip().split('\t')
                    break
        
        if fields is None:
            logger.warning(f"No #fields line found in {filepath}")
            return pd.DataFrame()
        
        # Read the actual data
        df = pd.read_csv(
            filepath,
            sep='\t',
            comment='#',
            names=fields,
            on_bad_lines='skip',
            engine='python'
        )
        
        return df
        
        if not dfs:
            logger.error("No valid connection data loaded")
            return pd.DataFrame()
        
        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"Total connections loaded: {len(df)}")
        
        return df
    
    def preprocess_connections(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Preprocess connection data for windowing
        
        Parameters:
        -----------
        df : pd.DataFrame
            Raw Zeek connection logs
            
        Returns:
        --------
        pd.DataFrame
            Preprocessed data ready for sliding windows
        """
        
        if df.empty:
            return df
        
        df = df.copy()
        
        # Ensure required columns exist
        required_cols = ['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'proto', 'duration']
        for col in required_cols:
            if col not in df.columns:
                logger.warning(f"Missing column: {col}")
        
        # Convert timestamp to float if needed
        if 'ts' in df.columns:
            df['ts'] = pd.to_numeric(df['ts'], errors='coerce')
            df = df.dropna(subset=['ts'])
        
        # Handle missing values
        if 'duration' in df.columns:
            df['duration'] = pd.to_numeric(df['duration'], errors='coerce').fillna(0)
        
        # Sort by timestamp and IP
        df = df.sort_values(['id.orig_h', 'ts']).reset_index(drop=True)
        
        logger.info(f"Preprocessed {len(df)} connections")
        return df
    
    def generate_windowed_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Generate windowed dataset from connection logs
        
        Parameters:
        -----------
        df : pd.DataFrame
            Preprocessed connection logs
            
        Returns:
        --------
        pd.DataFrame
            Windowed dataset with aggregated features
        """
        
        if df.empty:
            logger.error("Cannot generate windows from empty data")
            return pd.DataFrame()
        
        logger.info(f"Creating sliding windows (size={self.window_config.window_size_seconds}s, "
                   f"step={self.window_config.step_size_seconds}s)")
        
        windowed_df = self.analyzer.transform(df)
        
        if windowed_df.empty:
            logger.error("No windows generated")
            return pd.DataFrame()
        
        logger.info(f"Generated {len(windowed_df)} windows")
        
        # Add dataset-specific features
        windowed_df = self._add_dataset_features(windowed_df, df)
        
        return windowed_df
    
    def _add_dataset_features(self, windowed_df: pd.DataFrame, original_df: pd.DataFrame) -> pd.DataFrame:
        """
        Add custom features to windowed data for attack detection
        
        Parameters:
        -----------
        windowed_df : pd.DataFrame
            Windowed aggregations
        original_df : pd.DataFrame
            Original connection logs (for detailed analysis)
            
        Returns:
        --------
        pd.DataFrame
            Windowed data with additional features
        """
        
        df = windowed_df.copy()
        
        # Calculate burst_score for each window
        # burst_score = connections in 10s / connections in 60s
        # (high burst = concentrated activity)
        
        df['burst_score'] = 0.0
        df['interval_stddev'] = 0.0
        df['recent_activity_score'] = 0.0
        
        # Global max for normalization
        global_max_recent = original_df.groupby('id.orig_h').size().max()
        
        for idx, row in df.iterrows():
            ip = row['id.orig_h']
            window_start = row['window_start']
            window_end = row['window_end']
            
            # Get original data for this window and IP
            ip_window_data = original_df[
                (original_df['id.orig_h'] == ip) &
                (original_df['ts'] >= window_start) &
                (original_df['ts'] < window_end)
            ]
            
            if len(ip_window_data) > 0:
                # Burst score (concentration)
                window_duration = window_end - window_start
                conn_count = len(ip_window_data)
                
                # Simple burst indicator: high connections in short time
                if window_duration > 0:
                    df.at[idx, 'burst_score'] = min(1.0, conn_count / 10.0)  # Normalize to [0,1]
                
                # Interval regularity (if multiple connections)
                if len(ip_window_data) > 1 and 'ts' in ip_window_data.columns:
                    intervals = ip_window_data['ts'].diff().dropna().values
                    if len(intervals) > 0:
                        df.at[idx, 'interval_stddev'] = float(np.std(intervals))
                
                # Recent activity score (normalized by global max)
                recent_count = len(ip_window_data)
                df.at[idx, 'recent_activity_score'] = min(1.0, recent_count / max(global_max_recent, 1))
        
        return df
    
    def export_dataset(self, windowed_df: pd.DataFrame, output_path: str = None) -> str:
        """
        Export windowed dataset to CSV
        
        Parameters:
        -----------
        windowed_df : pd.DataFrame
            Windowed dataset to export
        output_path : str
            Path to save the dataset (auto-generated if None)
            
        Returns:
        --------
        str
            Path to saved file
        """
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"windowed_dataset_{timestamp}.csv"
        
        # Select and order columns for output
        cols_to_keep = [
            'id.orig_h', 'window_start', 'window_end', 'window_duration',
            'n_connections', 'burst_score', 'interval_stddev', 'recent_activity_score'
        ]
        
        # Add aggregated columns if they exist
        agg_cols = [c for c in windowed_df.columns if c.endswith('_mean') or c.endswith('_std') or c.endswith('_max')]
        cols_to_keep.extend(agg_cols[:10])  # Limit to avoid too many columns
        
        # Keep only existing columns
        cols_to_export = [c for c in cols_to_keep if c in windowed_df.columns]
        
        export_df = windowed_df[cols_to_export].copy()
        
        # Save to CSV
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        export_df.to_csv(output_path, index=False)
        
        logger.info(f"✅ Exported {len(export_df)} windows to {output_path}")
        logger.info(f"   Columns: {len(export_df.columns)}")
        logger.info(f"   Size: {Path(output_path).stat().st_size / 1024:.1f} KB")
        
        return output_path
    
    def generate(self, output_path: str = None) -> Tuple[pd.DataFrame, str]:
        """
        Complete pipeline: load, preprocess, window, export
        
        Parameters:
        -----------
        output_path : str
            Path to save the dataset
            
        Returns:
        --------
        Tuple[pd.DataFrame, str]
            (windowed_dataset, output_file_path)
        """
        
        logger.info("=" * 70)
        logger.info("WINDOWED DATASET GENERATION")
        logger.info("=" * 70)
        
        # Load
        df = self.load_zeek_conn_logs()
        if df.empty:
            return df, None
        
        # Preprocess
        df = self.preprocess_connections(df)
        if df.empty:
            return df, None
        
        # Window
        windowed_df = self.generate_windowed_dataset(df)
        if windowed_df.empty:
            return windowed_df, None
        
        # Analyze
        stats = analyze_windows(windowed_df, output_stats=True)
        
        # Export
        saved_path = self.export_dataset(windowed_df, output_path)
        
        logger.info("=" * 70)
        
        return windowed_df, saved_path


# Convenience function for Merger integration
def generate_windowed_dataset(
    zeek_logs_dir: str = "/zeek_logs",
    output_dir: str = "/app/data",
    window_size: float = 30.0,
    step_size: float = 5.0
) -> str:
    """
    Generate and export windowed dataset from Zeek logs
    
    Parameters:
    -----------
    zeek_logs_dir : str
        Directory containing Zeek logs
    output_dir : str
        Directory to save the dataset
    window_size : float
        Sliding window size in seconds
    step_size : float
        Sliding window step size in seconds
        
    Returns:
    --------
    str
        Path to the generated dataset
    """
    
    generator = WindowedDatasetGenerator(
        zeek_logs_dir=zeek_logs_dir,
        window_size_seconds=window_size,
        step_size_seconds=step_size
    )
    
    output_path = str(Path(output_dir) / "windowed_dataset.csv")
    windowed_df, saved_path = generator.generate(output_path)
    
    return saved_path or output_path
