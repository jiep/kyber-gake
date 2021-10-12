import sys
import yaml
import subprocess
import os
from shutil import copy
from pathlib import Path
from netaddr import IPNetwork

DOCKERFILE_STR = """
FROM ubuntu:20.04

WORKDIR /gake
COPY {bin} .
COPY {keys} keys.bin
COPY {ca} {ca}
COPY {ips} ips.txt
EXPOSE 8080
ENTRYPOINT ["./{bin}", "keys.bin", "{ca}", "ips.txt", "{ip}"]
"""

DOCKERCOMPOSE_PARTY_STR = """
    party{i}:
      build:
        context: .
        dockerfile: {dockerfile}
      ports:
       - "{port}:8080"
      networks:
        vpcbr:
          ipv4_address: {ip}
"""

DOCKERCOMPOSE_STR = """
version: '2'

services:
  {parties}

networks:
  vpcbr:
    driver: bridge
    ipam:
     config:
       - subnet: {subnet}
         gateway: {gateway}
"""

def create_keys_ca(bin, ips_file, ca_file, output):
    binary = "{bin} {ca_file} {ips_file} {output}".format(bin=bin, ca_file=ca_file, ips_file=ips_file, output=output)
    output = subprocess.Popen(binary, shell=True, stdout=subprocess.PIPE).stdout.read().decode("utf-8")
    return output

def generate_ips(n, subnet):
    network = IPNetwork(subnet)
    network = list(network)
    assert(len(network) >= n)
    ips = network[2:n+2]
    ips = list(map(str, ips))
    return ips

def save_ips(filename, ips):
    ips = "\n".join(ips) + "\n"
    with open(filename, "w") as f:
        f.write(ips)

def save_dockerfiles(filename, dockerfile):
     with open(filename, "w") as f:
         f.write(dockerfile)

def create_dockerfile(filename, ip, ca, ips, impl, sec_level, bin):
    dockerfile = DOCKERFILE_STR.format(
        keys=ip + ".bin",
        ca=ca,
        ip=ip,
        ips=ips,
        impl=impl,
        sec_level=sec_level,
        bin=bin
    )
    return dockerfile

def create_dockercompose(ips, dockerfiles, gateway, subnet):
    parties = ""
    port = 8080
    for (i, ip) in enumerate(ips):
        parties += DOCKERCOMPOSE_PARTY_STR.format(i=i, dockerfile=dockerfiles[i], ip=ip, port=port + i)
    dockercompose = DOCKERCOMPOSE_STR.format(parties=parties, subnet=subnet, gateway=gateway)
    return dockercompose

def save_dockercompose(filename, dockercompose):
    with open(filename, "w") as f:
        f.write(dockercompose)

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
    filename = config["ips"]
    dockerfile_name = config["dockerfile"]
    dockercompose_name = config["docker-compose"]
    implementations = config["implementations"]
    sec_levels = config["sec-levels"]
    subnet = config["subnet"]
    gateway = config["gateway"]
    input = config["input"]
    output = config["output"]

    try:
        os.mkdir(config["output"])
    except Exception as e:
        print ("Unable to create folder!")
        # sys.exit(1)

    for n in N:
        path = os.path.join(config["output"], str(n))
        try:
            os.mkdir(path)
        except Exception as e:
            print ("Unable to create folder!")
        for type in ["qrom", "rom"]:
            ca_config = config[type]
            print(ca_config["ca"])
            path_type = os.path.join(path, type)
            print(path_type)
            try:
                os.mkdir(path_type)
            except Exception as e:
                print ("Unable to create folder!")
            for implementation in implementations:
                path_impl = os.path.join(path_type, implementation)
                try:
                    os.mkdir(path_impl)
                except Exception as e:
                    print ("Unable to create folder!")
                for sl in sec_levels:
                    path_level = os.path.join(path_impl, str(sl))
                    try:
                        os.mkdir(path_level)
                    except Exception as e:
                        print ("Unable to create folder!")

                    ips = generate_ips(n, subnet)
                    dockerfiles = []
                    print(ca_config["ca"])
                    for ip in ips:
                        bin = ca_config["bin"].format(impl=implementation, sec_level=sl)
                        dockerfile = create_dockerfile(None, ip, ca_config["ca"], filename, implementation, sl, os.path.basename(bin))
                        # print(dockerfile)
                        ip_dockerfile = dockerfile_name.format(ip=ip)
                        path_dockerfile = os.path.join(path_level, ip_dockerfile)
                        dockerfiles.append(ip_dockerfile)
                        # print(path_dockerfile)
                        save_dockerfiles(path_dockerfile, dockerfile)
                    dockercompose = create_dockercompose(ips, dockerfiles, gateway, subnet)
                    # print(dockercompose)
                    path_dockercompose = os.path.join(path_level, dockercompose_name)
                    # print(path_dockercompose)
                    save_dockercompose(path_dockercompose, dockercompose)
                    ca_bin = ca_config["ca-bin"].format(impl=implementation, sec_level=sl)

                    path_ca = os.path.join(path_level, ca_config["ca"])
                    path_ca_bin = os.path.join(input, ca_bin)
                    print(ca_bin)
                    print(path_ca)

                    path_ips = os.path.join(path_level, filename)
                    save_ips(path_ips, ips)
                    a = create_keys_ca(path_ca_bin, path_ips, path_ca, path_level)
                    # print(a)
                    path_bin = os.path.join(input, bin)
                    print(path_bin)
                    copy(path_bin, path_level)

if __name__ == "__main__":
    main()
