#!/usr/bin/env python3

import subprocess
import numpy as np
import re

SECURITY = [512, 768, 1024]
TYPE = ["QROM", "ROM"]
NUM_PARTIES = [2, 10, 50, 100]
TRIALS = 10
FOLDER = "build/ref"
BINARY = "test_gake"
OUTPUT_FOLDER = "results"

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

# print(parse(""))

results = np.zeros((len(SECURITY), len(NUM_PARTIES), len(TYPE), TRIALS, 10))
# print(results.shape)

results_file = open("{}/results.csv".format(OUTPUT_FOLDER), "w")
results_file.write("security,parties,type,time_init,time_round12,time_round3,time_round4,time_total,percentage_init,percentage_round12,percentage_round3,percentage_round4,percentage_total\n")
for (i, security) in enumerate(SECURITY):
    for (j, parties) in enumerate(NUM_PARTIES):
        for (k, type) in enumerate(TYPE):
            for trial in range(TRIALS):
                if type == "QROM":
                    bin = "{}/{}_qrom{}_ref {}".format(FOLDER, BINARY, security, parties)
                else:
                    bin = "{}/{}{}_ref {}".format(FOLDER, BINARY, security, parties)

                print("({}) {}".format(trial, bin))

                output = subprocess.Popen(bin, shell=True, stdout=subprocess.PIPE).stdout.read()
                # results[i][j][k][trial][:] = parse(output)
                # print(output)
                results_file.write("{},{},{},{}\n".format(security, parties, type, ",".join(parse(output))))
                print(parse(output))

results_file.close()

# print(results)
# np.save("{}/results.npy".format(OUTPUT_FOLDER), results)
