"""
Window Parameter Optimizer
==========================

Automatic optimization of sliding window parameters based on
temporal density separation between attack and normal traffic.
"""

from dataclasses import dataclass
import pandas as pd
import numpy as np
from .config import WindowConfig
from .analyzer import SlidingWindowAnalyzer


# ------------------------------------------------------------------
# Dataclasses
# ------------------------------------------------------------------

@dataclass
class OptimizationResult:
    best_config_name: str
    best_config: WindowConfig
    scores: dict
    results: dict
    windowed_df: pd.DataFrame


# ------------------------------------------------------------------
# Core analysis functions
# ------------------------------------------------------------------

def analyze_temporal_density(df: pd.DataFrame):
    densities = []

    for ip in df['id.orig_h'].unique():
        ip_data = df[df['id.orig_h'] == ip].sort_values('ts')
        if len(ip_data) < 2:
            continue

        intervals = ip_data['ts'].diff().dropna()

        densities.append({
            'ip': ip,
            'is_attack_ip': ip_data['is_attack'].mean() > 0.5,
            'mean_interval': intervals.mean(),
            'median_interval': intervals.median(),
            'min_interval': intervals.min(),
            'max_interval': intervals.max(),
        })

    density_df = pd.DataFrame(densities)
    attack_ips = density_df[density_df['is_attack_ip']]
    normal_ips = density_df[~density_df['is_attack_ip']]

    return density_df, attack_ips, normal_ips


def recommend_window_strategies(attack_ips, normal_ips):
    if attack_ips.empty:
        return None

    attack_burst = attack_ips['max_interval'].mean()
    attack_interval = attack_ips['median_interval'].median()

    strategies = {
        'small': dict(
            window_size=min(attack_burst * 1.5, 5.0),
            step_size=max(attack_interval * 0.5, 0.5),
        ),
        'medium': dict(
            window_size=min(attack_burst * 3.0, 15.0),
            step_size=min((attack_burst * 3.0) / 3, 5.0),
        ),
        'large': dict(
            window_size=30.0,
            step_size=5.0,
        ),
    }

    return strategies


def evaluate_strategies(df, strategies):
    results = {}

    for name, params in strategies.items():
        config = WindowConfig(
            window_size_seconds=round(params['window_size'], 2),
            step_size_seconds=round(params['step_size'], 2),
            label_strategy='any'
        )

        analyzer = SlidingWindowAnalyzer(config)
        windowed = analyzer.transform(df)

        attack_windows = windowed['is_attack_any'].sum()
        mixed = ((windowed['is_attack_ratio'] > 0) &
                 (windowed['is_attack_ratio'] < 1)).sum()

        avg_attack = windowed[windowed['is_attack_any'] == 1]['n_connections'].mean()
        avg_normal = windowed[windowed['is_attack_any'] == 0]['n_connections'].mean()

        results[name] = {
            'config': config,
            'windowed_df': windowed,
            'purity': (1 - mixed / len(windowed)) * 100,
            'attack_pct': attack_windows / len(windowed) * 100,
            'separation': avg_attack / (avg_normal + 1e-6),
            'total_windows': len(windowed),
            'avg_conns_attack': avg_attack,
        }

    return results


def select_best_configuration(results):
    scores = {}

    for name, res in results.items():
        score = 0
        if res['purity'] > 95:
            score += 3
        if res['separation'] > 2.0:
            score += 3
        if 1_000 < res['total_windows'] < 50_000:
            score += 2
        if 10 < res['attack_pct'] < 60:
            score += 2
        if res['avg_conns_attack'] > 3:
            score += 1

        scores[name] = score

    best_name = max(scores, key=scores.get)
    return best_name, scores


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def optimize_window_parameters(df: pd.DataFrame) -> OptimizationResult:
    _, attack_ips, normal_ips = analyze_temporal_density(df)
    strategies = recommend_window_strategies(attack_ips, normal_ips)

    if strategies is None:
        raise ValueError("Not enough attack traffic to optimize windows")

    results = evaluate_strategies(df, strategies)
    best_name, scores = select_best_configuration(results)

    best = results[best_name]

    return OptimizationResult(
        best_config_name=best_name,
        best_config=best['config'],
        scores=scores,
        results=results,
        windowed_df=best['windowed_df']
    )
