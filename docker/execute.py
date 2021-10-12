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

    try:
        os.mkdir(config["output"])
    except Exception as e:
        print ("Unable to create folder!")
        # sys.exit(1)

    docker_composes = glob.glob(input + '/**/**/**/docker-compose.yml', recursive=True)
    mycwd = os.getcwd()
    for f in docker_composes:
        abs_path = os.path.abspath(os.path.dirname(f))
        print(os.path.dirname(f))
        os.chdir(abs_path)
        print("---------------------")
        binary = "docker network rm $(docker network ls -q --filter='name=vpcbr'); docker-compose up --build"
        output = subprocess.Popen(binary, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")
        print(f)
        os.chdir(mycwd)


if __name__ == "__main__":
    main()
