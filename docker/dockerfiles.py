import sys
import yaml
import subprocess
from pathlib import Path
from netaddr import IPNetwork

DOCKERFILE_STR = """
FROM ubuntu:20.04

WORKDIR /gake
COPY ./ref/gake_network1024_ref .
COPY {keys} keys.bin
COPY {ca} ca.bin
COPY {ips} ips.txt
EXPOSE 8080
ENTRYPOINT ["./gake_network1024_ref", "keys.bin", "ca.bin", "ips.txt", "{ip}"]
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

def create_dockerfile(filename, ip):
    dockerfile = DOCKERFILE_STR.format(keys=ip + ".bin", ca="ca.bin", ip=ip, ips="ips.txt")
    return dockerfile

def create_dockercompose(ips, dockerfiles, gateway, subnet):
    parties = ""
    for (i, ip) in enumerate(ips):
        port = 8080
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

    n = config["N"]
    filename = config["ips"]
    ca_filename = config["ca"]
    subnet = config["subnet"]
    gateway = config["gateway"]
    dockerfile_name = config["dockerfile"]
    dockercompose_name = config["docker-compose"]
    output = config["output"]
    ips = generate_ips(n, subnet)
    dockerfiles = []
    save_ips(filename, ips)
    for ip in ips:
        dockerfile = create_dockerfile(None, ip)
        filename_dockerfile = dockerfile_name.format(ip=ip)
        dockerfiles.append(filename_dockerfile)
        save_dockerfiles(output + "/" + filename_dockerfile, dockerfile)
    dockercompose = create_dockercompose(ips, dockerfiles, gateway, subnet)
    save_dockercompose(output + "/" + dockercompose_name, dockercompose)
    a = create_keys_ca(config["ca-bin"], filename, ca_filename, output)
    print(a)

if __name__ == "__main__":
    main()
