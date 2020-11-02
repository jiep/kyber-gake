# Kyber

## How to run

1. Install [Docker](https://www.docker.com)

2. Build image

```bash
docker build -t kyber .
```

3. Run container

```bash
docker run kyber
```

## Development

1. Run

```bash
docker run -it -v `pwd`:/kyber kyber bash
```
