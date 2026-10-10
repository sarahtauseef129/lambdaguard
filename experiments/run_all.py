"""Run every experiment.   python -m experiments.run_all"""
from experiments import compare_rankings, weight_sweep

if __name__ == "__main__":
    compare_rankings.main()
    weight_sweep.main()
