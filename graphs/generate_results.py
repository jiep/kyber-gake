#!/usr/bin/env python3

import subprocess
import numpy as np
import re
import yaml
import sys
import signal
from pathlib import Path

def parse(output):
    m = re.search('''Time stats
	Init time      : (.+?)s \((.+?)%\)
	Round 1-2 time : (.+?)s \((.+?)%\)
	Round 3 time   : (.+?)s \((.+?)%\)
	Round 4 time   : (.+?)s \((.+?)%\)
	Total time     : (.+?)s \((.+?)%\)
''', output)
    if m:
        return [
            m.group(1), m.group(3), m.group(5), m.group(7), m.group(9),
            m.group(2), m.group(4), m.group(6), m.group(8), m.group(10)
        ]
    else:
        return ["1"]*10

def main():

    SECURITY = [512, 768, 1024]
    TYPE = ["QROM", "ROM"]

    if(len(sys.argv) != 2):
        print("You must provide a config file (e.g. config.yaml)", flush=True)
        sys.exit(1)

    file = sys.argv[1]
    if not Path(file).is_file():
        print("File {} does NOT exist".format(file), flush=True)
        sys.exit(1)

    with open(file) as f:
        config = yaml.load(f, Loader=yaml.SafeLoader)

    results = np.zeros((len(SECURITY), len(config["NUM_PARTIES"]), len(TYPE), config["TRIALS"], 10))

    results_file = open("{}/results.csv".format(config["OUTPUT_FOLDER"]), "w")
    results_file.write("security,parties,type,time_init,time_round12,time_round3,time_round4,time_total,percentage_init,percentage_round12,percentage_round3,percentage_round4,percentage_total\n")
    for (i, security) in enumerate(SECURITY):
        for (j, parties) in enumerate(config["NUM_PARTIES"]):
            for (k, type) in enumerate(TYPE):
                for trial in range(config["TRIALS"]):
                    if type == "QROM":
                        bin = "{}/{}_qrom{}_ref {}".format(config["FOLDER"], config["BINARY"], security, parties)
                    else:
                        bin = "{}/{}{}_ref {}".format(config["FOLDER"], config["BINARY"], security, parties)

                    print("({}) {}".format(trial, bin), flush=True)

                    output = str(subprocess.Popen(bin, shell=True, stdout=subprocess.PIPE).stdout.read())

                    results_file.write("{},{},{},{}\n".format(security, parties, type, ",".join(parse(output))))
                    # print(parse(output))

    results_file.close()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
