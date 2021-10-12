import sys
import yaml
import glob
import os
import subprocess
from pathlib import Path

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

    N = config["N"]
    input = config["output"]
    output = config["results_output"]
    implementations = config["implementations"]
    sec_levels = config["sec-levels"]

    try:
        os.mkdir(output)
    except Exception as e:
        print ("Unable to create folder!")
        # sys.exit(1)

    mycwd = os.getcwd()
    for n in N:
        path = os.path.join(output, str(n))
        path_in = os.path.join(input, str(n))
        print("path:", path)
        try:
            os.mkdir(path)
        except Exception as e:
            print ("Unable to create folder!")

        for type in ["qrom", "rom"]:
            path_type = os.path.join(path, type)
            path_in_type = os.path.join(path_in, type)
            try:
                os.mkdir(path_type)
            except Exception as e:
                print ("Unable to create folder!")

            ca_config = config[type]

            for implementation in implementations:
                path_impl = os.path.join(path_type, implementation)
                path_in_impl = os.path.join(path_in_type, implementation)
                try:
                    os.mkdir(path_impl)
                except Exception as e:
                    print ("Unable to create folder!")

                for sl in sec_levels:
                    path_level = os.path.join(path_impl, str(sl))
                    path_in_level = os.path.join(path_in_impl, str(sl))
                    try:
                        os.mkdir(path_level)
                    except Exception as e:
                        print ("Unable to create folder!")

                    abs_path = os.path.abspath(path_in_level)
                    os.chdir(abs_path)
                    # print(path_in_level)
                    binary = "docker network rm $(docker network ls -q --filter='name=vpcbr'); docker-compose up --build --remove-orphans"
                    # output = subprocess.Popen(binary, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")
                    os.chdir(mycwd)
                    for party in range(n):
                        log_path = os.path.abspath(os.path.join(path_level, "party" + str(party) + ".log"))
                        print("log", log_path)
                        binary2 = "docker-compose logs party{} > {}".format(party, log_path)
                        output2 = subprocess.Popen(binary2, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")
                        with open(log_path,"w") as f:
                            f.write(output2)


if __name__ == "__main__":
    main()
