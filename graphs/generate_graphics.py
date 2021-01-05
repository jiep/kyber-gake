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
IMPLEMENTATIONS = ["avx2", "ref"]


def plot_total_time_by_time(data, config):

    fig, axes = plt.subplots(2,4, figsize=(25,10), sharey=False)
    fig.suptitle('Total time')
    fig.subplots_adjust(hspace=0.5, wspace=0.5)

    for (j, impl) in enumerate(IMPLEMENTATIONS):
        df = data[data['implementation'] == impl]
        for (i, sec) in enumerate(SECURITY):
            df2 = df[df["security"] == sec]
            df2 = df2[['parties', 'type', 'time_total']]

            if i == 0:
                axes[j,i].text(1, 0.5, impl, horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].text(0, 0.5, 'Implementation', horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].axis('off')


            sns.lineplot(ax=axes[j,i+1], x="parties", y="time_total", hue="type", data=df2)
            axes[j,i+1].set(xlabel='Number of parties', ylabel='Total time (seconds)')
            axes[j,i+1].set_title('Security level: {}'.format(sec))
            axes[j,i+1].legend(loc='upper left')


    figname = "{}/totaltime.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)

def plot_total_time_by_round(data, config):

    fig, axes = plt.subplots(2,4, figsize=(25,10))
    fig.suptitle('Percentage of total time per round')
    fig.subplots_adjust(hspace=0.5, wspace=0.5)

    for (j, impl) in enumerate(IMPLEMENTATIONS):
        df = data[data['implementation'] == impl]
        for (i, sec) in enumerate(SECURITY):
            df2 = df[df["security"] == sec]
            df2 = df2[['type', 'percentage_init', 'percentage_round12', 'percentage_round3', 'percentage_round4']]
            df2.columns = ['type', 'Init', 'Round 1-2', 'Round 3', 'Round 4']
            df2 = df2.melt(id_vars=["type"], var_name="Round", value_name="Percentage")

            # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
            #     print(df2)

            if i == 0:
                axes[j,i].text(1, 0.5, impl, horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].text(0, 0.5, 'Implementation', horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].axis('off')

            sns.boxplot(ax=axes[j,i+1], x="Round", y="Percentage", hue="type", data=df2)
            axes[j,i+1].set_title('Security level: {}'.format(sec))
            axes[j,i+1].legend(loc='upper left')

    figname = "{}/totaltime_round.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)

def plot_speed_commitments(data, config):

    fig, axes = plt.subplots(2,3, figsize=(20,10))
    fig.suptitle('Commitment operations')
    fig.subplots_adjust(hspace=0.5, wspace=0.5)

    commitment_vars = ['time_commit', 'time_check']
    commitment_vars_names = ['Commitment time', 'Check commitment']
    for (i, var) in enumerate(commitment_vars):
        for (j, impl) in enumerate(IMPLEMENTATIONS):
            df = data[data['implementation'] == impl]

            df2 = df[['security','type', var]]
            df2.loc[:, str(var)] = df2[str(var)].apply(lambda x: 1000*x)

            # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
            #     print(df2)

            if i == 0:
                axes[j,i].text(1, 0.5, impl, horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].text(0, 0.5, 'Implementation', horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].axis('off')

            sns.boxplot(ax=axes[j,i+1], x="security", y=str(var), hue="type", data=df2)
            axes[j,i+1].set_title(commitment_vars_names[i])
            axes[j,i+1].legend(loc='upper left')
            axes[j,i+1].set(xlabel='Security level', ylabel='Time (milliseconds)')

    figname = "{}/totaltime_commitments.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)


def plot_speed_2_ake(data, config):

    fig, axes = plt.subplots(2,4, figsize=(25,10))
    fig.suptitle('2-AKE operations')
    fig.subplots_adjust(hspace=0.5, wspace=0.5)

    commitment_vars = ['time_init', 'time_der_resp', 'time_der_init']
    commitment_vars_names = ['Init time', 'Der_resp time', 'Der_init time']
    for (i, var) in enumerate(commitment_vars):
        for (j, impl) in enumerate(IMPLEMENTATIONS):
            df = data[data['implementation'] == impl]

            df2 = df[['security','type', var]]
            df2.loc[:, str(var)] = df2[str(var)].apply(lambda x: 1000*x)

            # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
            #     print(df2)

            if i == 0:
                axes[j,i].text(1, 0.5, impl, horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].text(0, 0.5, 'Implementation', horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].axis('off')

            sns.boxplot(ax=axes[j,i+1], x="security", y=str(var), hue="type", data=df2)
            axes[j,i+1].set_title(commitment_vars_names[i])
            axes[j,i+1].legend(loc='upper left')
            axes[j,i+1].set(xlabel='Security level', ylabel='Time (milliseconds)')

    figname = "{}/totaltime_2_AKE.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)

def plot_speed_kem(data, config):

    fig, axes = plt.subplots(2,4, figsize=(25,10))
    fig.suptitle('KEM operations')
    fig.subplots_adjust(hspace=0.5, wspace=0.5)

    commitment_vars = ['time_keygen', 'time_encaps', 'time_decaps']
    commitment_vars_names = ['Key generation time', 'Encapsulation time', 'Decapsulation time']
    for (i, var) in enumerate(commitment_vars):
        for (j, impl) in enumerate(IMPLEMENTATIONS):
            df = data[data['implementation'] == impl]

            df2 = df[['security','type', var]]
            df2.loc[:, str(var)] = df2[str(var)].apply(lambda x: 1000*x)

            # with pd.option_context('display.max_rows', None, 'display.max_columns', None):
            #     print(df2)

            if i == 0:
                axes[j,i].text(1, 0.5, impl, horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].text(0, 0.5, 'Implementation', horizontalalignment='center', verticalalignment='center', transform=axes[j,i].transAxes)
                axes[j,i].axis('off')

            sns.boxplot(ax=axes[j,i+1], x="security", y=str(var), hue="type", data=df2)
            axes[j,i+1].set_title(commitment_vars_names[i])
            axes[j,i+1].legend(loc='upper left')
            axes[j,i+1].set(xlabel='Security level', ylabel='Time (milliseconds)')

    figname = "{}/totaltime_kem.png".format(config["OUTPUT_FOLDER"])
    fig.savefig(figname)
    print("Saved file to {}".format(figname), flush=True)

def main():
    pd.options.mode.chained_assignment = None

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
        print("File {} does NOT exist".format(results_file), flush=True)
        sys.exit(1)

    results_speed_file = "{}/results_speed.csv".format(config["OUTPUT_FOLDER"])
    if not Path(results_speed_file).is_file():
        print("File {} does NOT exist".format(results_speed_file), flush=True)
        sys.exit(1)

    data = pd.read_csv(results_file)
    data_speed = pd.read_csv(results_speed_file)

    plot_total_time_by_time(data, config)
    plot_total_time_by_round(data, config)
    plot_speed_commitments(data_speed, config)
    plot_speed_2_ake(data_speed, config)
    plot_speed_kem(data_speed, config)

if __name__ == '__main__':
    main()
