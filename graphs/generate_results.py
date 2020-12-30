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
        print("Not found", flush=True)
        return ["1"]*10

def parse_speed(output, type):

    m_rom = '''Commitment
	Commit time: (.+?)s
	Check  time: (.+?)s


2-AKE
	initA   time: (.+?)s
	sharedB time: (.+?)s
	sharedA time: (.+?)s


KEM
	keygen time: (.+?)s
	encaps time: (.+?)s
	decaps time: (.+?)s
'''

    m_qrom = '''Commitment
	Commit time: (.+?)s
	Check  time: (.+?)s


2-AKE
	init     time: (.+?)s
	der_resp time: (.+?)s
	der_init time: (.+?)s


KEM
	keygen time: (.+?)s
	encaps time: (.+?)s
	decaps time: (.+?)s
'''
    if type == "ROM":
        m = re.search(m_rom, output)
    elif type == "QROM":
        m = re.search(m_qrom, output)
    else:
        print("Not valid option", flush=True)

    if m:
        return [
            m.group(1), m.group(2), m.group(3), m.group(4),
            m.group(5), m.group(6), m.group(7), m.group(8)
        ]
    else:
        print("Not found", flush=True)
        return ["1"]*8

def main():

    SECURITY = [512, 768, 1024]
    TYPE = ["QROM", "ROM"]
    IMPLEMENTATIONS = ["avx2", "ref"]

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

    results_file = open("{}/results.csv".format(config["OUTPUT_FOLDER"]), "w", buffering=1)
    results_speed_file = open("{}/results_speed.csv".format(config["OUTPUT_FOLDER"]), "w", buffering=1)
    results_file.write("implementation,security,parties,type,time_init,time_round12,time_round3,time_round4,time_total,percentage_init,percentage_round12,percentage_round3,percentage_round4,percentage_total\n")
    results_speed_file.write("implementation,security,parties,type,time_commit,time_check,time_init,time_der_resp,time_der_init,time_keygen,time_encaps,time_decaps\n")
    for implementation in IMPLEMENTATIONS:
        for (i, security) in enumerate(SECURITY):
            for (j, parties) in enumerate(reversed(config["NUM_PARTIES"])):
                for (k, type) in enumerate(TYPE):
                    for trial in range(config["TRIALS"]):
                        if type == "QROM":
                            bin = "{}/{}/{}_qrom{}_{} {}".format(config["FOLDER"], implementation, config["BINARY"], security, implementation, parties)
                            bin_speed = "{}/{}/{}_qrom_speed{}_{} {}".format(config["FOLDER"], implementation, config["BINARY"], security, implementation, config["TRIALS_SPEED"])
                        else:
                            bin = "{}/{}/{}{}_{} {}".format(config["FOLDER"], implementation, config["BINARY"], security, implementation, parties)
                            bin_speed = "{}/{}/{}_speed{}_{} {}".format(config["FOLDER"], implementation, config["BINARY"], security, implementation, config["TRIALS_SPEED"])

                        print("({}) {}".format(trial, bin), flush=True)
                        output = subprocess.Popen(bin, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")

                        print("({}) {}".format(trial, bin_speed), flush=True)
                        output_speed = subprocess.Popen(bin_speed, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")


                        results_file.write("{},{},{},{},{}\n".format(implementation, security, parties, type, ",".join(parse(output))))
                        results_speed_file.write("{},{},{},{},{}\n".format(implementation, security, parties, type, ",".join(parse_speed(output_speed, type))))

    results_file.close()
    results_speed_file.close()

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    main()
