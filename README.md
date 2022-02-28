# Compiled-Kyber Group Authenticated Group Key Exchange (GAKE)

![Build](https://github.com/jiep/kyber/workflows/Build/badge.svg)

This repository contains the implementation of ["Compiled Constructions towards Post-Quantum Group Key Exchange: A Design from Kyber"](https://www.mdpi.com/2227-7390/8/10/1853).

## What is Kyber?

[Kyber](https://www.pq-crystals.org/kyber/) is a key encapsulation mechanism (KEM) and a finalist in [round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) of the [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) standardization project.

## Binaries

Download the latest version from [Releases](https://github.com/jiep/kyber-gake/releases).


## How to build

```bash
bash build.sh
```

### Prerequisites

* CMake
* OpenSSL

### How to build with Docker

1. Install [Docker](https://www.docker.com)

2. Build image

```bash
docker build -t kyber-gake .
```

3. Run container

```bash
docker run -it kyber-gake bash
```

## Test programs

Code contains two implementations of the GAKE: `ref` and `avx2`. Test programs are located in these folders. Each test program contains a `_qrom` version.

### Available test programs

```bash
.
|-- avx2
|   |-- test_gake1024_avx2
|   |-- test_gake512_avx2
|   |-- test_gake768_avx2
|   |-- test_gake_qrom1024_avx2
|   |-- test_gake_qrom512_avx2
|   |-- test_gake_qrom768_avx2
|   |-- test_gake_qrom_speed1024_avx2
|   |-- test_gake_qrom_speed512_avx2
|   |-- test_gake_qrom_speed768_avx2
|   |-- test_gake_speed1024_avx2
|   |-- test_gake_speed512_avx2
|   `-- test_gake_speed768_avx2
`-- ref
    |-- test_gake1024_ref
    |-- test_gake512_ref
    |-- test_gake768_ref
    |-- test_gake_qrom1024_ref
    |-- test_gake_qrom512_ref
    |-- test_gake_qrom768_ref
    |-- test_gake_qrom_speed1024_ref
    |-- test_gake_qrom_speed512_ref
    |-- test_gake_qrom_speed768_ref
    |-- test_gake_speed1024_ref
    |-- test_gake_speed512_ref
    `-- test_gake_speed768_ref
```

## Performance results

Latest performance results can be found on [Releases](https://github.com/jiep/kyber-gake/releases) under folder `results`.

### KEM

#### ref

![KEM ref](./imgs/totaltime_kem_ref.png)

#### avx2

![KEM avx2](./imgs/totaltime_kem_avx2.png)


### Commitment

#### ref

![Commitment ref](./imgs/totaltime_commitment_ref.png)

#### avx2

![Commitment ref](./imgs/totaltime_commitment_avx2.png)

### 2-AKE

#### ref

![2-AKE ref](./imgs/totaltime_2_ake_ref.png)

#### avx2

![2-AKE avx2](./imgs/totaltime_2_ake_avx2.png)

## GAKE performance

### Time per number of parties

#### ref

![GAKE parties ref](./imgs/totaltime_ref.png)

#### avx2

![GAKE parties avx2](./imgs/totaltime_avx2.png)

### Time per round

#### ref

![GAKE round ref](./imgs/totaltime_round_ref.png)

#### avx2

![GAKE round avx2](./imgs/totaltime_round_avx2.png)


## References

* Escribano Pablos, J.I.; González Vasco, M.I.; Marriaga, M.E.; Pérez del Pozo, Á.L. "Compiled Constructions towards Post-Quantum Group Key Exchange: A Design from Kyber," 2020 Mathematics, 8, 1853, doi: 10.3390/math8101853
* Bos, J. et al., "CRYSTALS - Kyber: A CCA-Secure Module-Lattice-Based KEM," 2018 IEEE European Symposium on Security and Privacy (EuroS&P), 2018, pp. 353-367, doi: 10.1109/EuroSP.2018.00032.
