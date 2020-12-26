#!/usr/bin/env python3

import subprocess
import pandas as pd
import seaborn as sns
import numpy as np
import yaml
import sys
import signal
from pathlib import Path
from matplotlib import pyplot as plt

SECURITY = [512, 768, 1024]
TYPE = ["QROM", "ROM"]

def plot_total_time_by_time(data, config):

    fig, axes = plt.subplots(1,3, figsize=(16,8))
    fig.suptitle('Total time')

    for (i, sec) in enumerate(SECURITY):
        df = data[data['security'] == sec]
        df = df[['parties', 'type', 'time_total']]
        df = df.groupby(['type', 'parties']).agg({'time_total': np.mean})

        # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        #     print(df)

        sns.lineplot(ax=axes[i], x="parties", y="time_total", hue="type", data=df)
        axes[i].set(xlabel='Number of parties', ylabel='Total time (seconds)')
        axes[i].set_title('Security level: {}'.format(sec))

    figname = "{}/totaltime.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)

def plot_total_time_by_round(data, config):

    fig, axes = plt.subplots(1,3, figsize=(16,8))
    fig.suptitle('Total time')

    for (i, sec) in enumerate(SECURITY):
        df = data[data['security'] == sec]
        df = df[['type', 'time_init', 'time_round12', 'time_round3', 'time_round4']]
        df = df.groupby(['type']).agg({'time_init': np.mean, 'time_round12': np.mean, 'time_round3': np.mean, 'time_round4': np.mean}).unstack()

        # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
        #     print(df)

        ind = len(TYPE)
        axes[i].set_title('Security level: {}'.format(sec))
        p4 = axes[i].bar(ind, df['time_round4'], bottom=df['time_init'] + df['time_round12'] + df['time_round3'])
        p3 = axes[i].bar(ind, df['time_round3'], bottom=df['time_init'] + df['time_round12'])
        p2 = axes[i].bar(ind, df['time_round12'], bottom=df['time_init'])
        p1 = axes[i].bar(ind, df['time_init'])
        plt.legend((p1[0], p2[0], p3[0], p4[0]), ('Init time', 'Round 1-2 time', 'Round 3 time', 'Round 4 time'))

    figname = "{}/totaltime_bar.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)

def main():
    if(len(sys.argv) != 2):
        print("You must provide a config file (e.g. config.yaml)", flush=True)
        sys.exit(1)

    file = sys.argv[1]
    if not Path(file).is_file():
        print("File {} does NOT exist".format(file), flush=True)
        sys.exit(1)

    with open(file) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    results_file = "{}/results.csv".format(config["OUTPUT_FOLDER"])
    if not Path(results_file).is_file():
        print("File {} does NOT exist".format(file), flush=True)
        sys.exit(1)

    data = pd.read_csv(results_file)

    plot_total_time_by_time(data, config)
    plot_total_time_by_round(data, config)

if __name__ == '__main__':
    main()
