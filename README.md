# NSDA Artifact Evaluation Package

*NSDA Artifact Evaluation Package* accompanies the paper *Neurosymbolic Disassembly*. It contains the source code, configuration files, and datasets required to reproduce the evaluation results presented in the paper.

## Hardware Requirements

The artifact requires a machine equipped with a CUDA-compatible GPU. The minimum hardware requirements are listed below.

| Component        | Minimum Requirement             |
| :--------------- | :------------------------------ |
| **CPU**          | 4-core x86_64 processor         |
| **Memory (RAM)** | 64 GB                           |
| **GPU**          | 1× NVIDIA GPU (CUDA-compatible) |
| **GPU VRAM**     | 8 GB                            |
| **Storage**      | 20 GB available disk space      |
| **Network**      | Internet access required        |

## Software Requirements

For Docker-based execution, a Docker daemon with `nvidia-container-toolkit` installed is required. The provided Docker image is based on CUDA 12.8. Therefore, the host system must provide CUDA 12.8 or newer.

For native execution, the use of a Python virtual environment is recommended. The software versions used in our local environment are listed below:

| Dependency  | Version         |
| :---------- | :-------------- |
| **Ubuntu**  | 22.04           |
| **Python**  | 3.12            |
| **Ghidra**  | 11.3.2 (required) & 12.0.4 (optinal for Ghidra 12 experiment and *Segmented NSDA*)|
| **OpenJDK** | 21.0.7          |
| **Radare2** | 6.0.7           |

Additional Python dependencies are specified in `requirements-legacy.txt` and `requirements.txt`.

## Quick Start

*For users evaluating the artifact via Docker.*

The full evaluation may require **3–7 days** to complete, depending on the available hardware. Running the experiment inside a persistent terminal session (for example, `screen` or `tmux`) is therefore recommended.

Clone the repository and initialize all submodules. Git LFS is required because the Chromium dataset is provided through a submodule containing LFS-managed files.

```bash
# Install Git LFS if it is not already available
git lfs install

# Clone the repository
git clone https://github.com/gdjs2/NSDA.git
cd NSDA

# Initialize and update all submodules
git submodule update --init --recursive
```

Build the Docker image:

```bash
docker build -t nsda-ae .
```

Create directories for evaluation outputs and logs:

```bash
mkdir eval_results logs
```

Run the demo experiment [EST: 60 human minutes]:

```bash
docker run -v $(pwd)/eval_results:/NSDA/eval_results \
           -v $(pwd)/logs:/NSDA/logs \
           --gpus all --rm -it nsda-ae exp 0
```

Display the demo results:

```bash
docker run -v $(pwd)/eval_results:/NSDA/eval_results \
           --gpus all --rm -it nsda-ae \
           show 0 ./eval_results/exp_0_results.json
```

A summary table similar to the one below should be displayed and an pdf efficiency plot figure should be created at `./eval_results`:

| Dataset | GHIDRA Prec | GHIDRA Recall | GHIDRA F1 | DDISASM Prec | DDISASM Recall | DDISASM F1 | LOADSTAR Prec | LOADSTAR Recall | LOADSTAR F1 | NSDA Prec | NSDA Recall | NSDA F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Coreutils - ARM32 | 0.9989 | 0.9615 | 0.9799 | 0.9995 | 0.9908 | 0.9951 | 0.9990 | 0.8920 | 0.9424 | 0.9958 | 0.9992 | 0.9975 |
| Coreutils - MIPS | 1.0000 | 0.8523 | 0.9202 | 1.0000 | 0.9966 | 0.9983 | — | — | — | 1.0000 | 0.9798 | 0.9898 |
| Coreutils - ARM32 - LLVM | 0.9878 | 0.8066 | 0.8880 | 0.9909 | 0.9980 | 0.9944 | 1.0000 | 0.8781 | 0.9351 | 0.9872 | 0.9989 | 0.9930 |
| Coreutils - MIPS - LLVM | 1.0000 | 0.5842 | 0.7375 | 1.0000 | 0.9965 | 0.9982 | — | — | — | 1.0000 | 0.9651 | 0.9823 |
| OpenSSL - x64 | 0.9865 | 0.8823 | 0.9315 | 0.9563 | 0.9995 | 0.9774 | — | — | — | 0.9402 | 0.9968 | 0.9677 |
| PLC - NS1 | 0.9953 | 0.9913 | 0.9933 | — | — | — | 0.9981 | 0.9984 | 0.9982 | 0.9932 | 0.9913 | 0.9922 |
| PLC - NS2 | 0.9799 | 0.9832 | 0.9815 | — | — | — | 1.0000 | 0.9882 | 0.9941 | 0.9718 | 0.9832 | 0.9774 |
| PLC - NS3 | 0.9865 | 0.5858 | 0.7351 | — | — | — | 0.9994 | 0.9379 | 0.9676 | 0.9306 | 0.9576 | 0.9439 |


After confirming that the demo experiment completes successfully, start the full evaluation:

```bash
docker run -v $(pwd)/eval_results:/NSDA/eval_results \
           -v $(pwd)/logs:/NSDA/logs \
           --gpus all --rm -it nsda-ae exp 1
```

Display the evaluation results:

```bash
docker run -v $(pwd)/eval_results:/NSDA/eval_results \
           --gpus all --rm -it nsda-ae \
           show 1 ./eval_results/exp_1_results.json
```

## Environment Description

The artifact supports two execution environments:

1. **Ghidra 11.3.2** with the legacy PyGhidra API, described in `requirements.txt`. This environment provides the legacy PyGhidra API and may be deprecated in future releases. Because Ghidra 11.3.2 only supports the legacy API, and this was the original experimental environment used for *NSDA*, it is provided as the default configuration.

2. **Ghidra 12.0.4** with the newer PyGhidra API, described in `requirements.txt.12`. These APIs provide a more flexible interface for binary analysis with Ghidra.

## How to Run the Artifact

The artifact can be executed in two ways:

1. Docker (recommended)
2. Native Python virtual environment

Detailed instructions for both approaches are provided below.

### Docker

Two Dockerfiles are provided. They differ only in the Ghidra version and PyGhidra dependencies described in the [Environment Description](#environment-description).

1. `Dockerfile` (default): Ghidra 11.3.2 with the legacy PyGhidra API installed from `requirements.txt`.
2. `Dockerfile.12` (optional): Ghidra 12.0.4 with the newer PyGhidra API installed from `requirements.txt.12`.

To build the Docker image for Ghidra 11 with the legacy API:

```bash
docker build -t nsda-ae .
```

To build the Docker image for Ghidra 12 with the newer API:

```bash
docker build -f Dockerfile.12 -t nsda-ae:12 .
```

The resulting Docker image can then be used to run the experiments.

The following directories inside the container store experiment artifacts and should be mounted to the host when persistence is desired:

* `/NSDA/logs` — Stores experiment logs. Mount this directory if you want to monitor progress or inspect logs.
* `/NSDA/eval_results` — Stores evaluation results. **Mount this directory** if you want to preserve results after the container terminates or visualize them later.

### Local Environment

Using a Python virtual environment (for example, Conda) is recommended for installing dependencies and running the artifact natively. If you plan to run experiments of *NSDA w/ Ghidra 12* or *Segmented NSDA*, you should install the newer API environment, otherwise legacy API. 

You must first install Ghidra and its corresponding dependencies (for example, a JRE or JDK):

https://github.com/nationalsecurityagency/ghidra#install

Install the dependencies for the legacy API environment (Ghidra < 12) for main experiments:

```bash
pip install -r ./requirements.txt
```

Install the dependencies for the newer API environment (Ghidra ≥ 12) for :

```bash
pip install -r ./requirements.txt.12
```

## Running Experiments

### Preconfigured Experiment Configurations

Several preconfigured experiment configurations are provided in the `./configs` directory. Most configurations are intended to be executed in the legacy environment.

* `demo.toml` (legacy API): Demo experiment used to verify the environment. [EST: 60 Human Minutes]
* `main.toml` (legacy API): Reproduces all experiments reported in Table 4 and Figure 2. [Time: TODO]
* Sub-experiments of `main.toml` (legacy API):

  1. `coreutils-arm32-gcc.toml`
  2. `coreutils-arm32-llvm.toml`
  3. `coreutils-mips-gcc.toml`
  4. `coreutils-mips-llvm.toml`
  5. `loadstar-plc.toml`
  6. `openssl-x64.toml`
* `main-12.toml` (new API): Reproduces experiments reported in Appendix B. [Time: TODO]
* `chromium-pe-x64.toml` (new API): Reproduces the *Segmented NSDA* experiment on Chromium. [Time: TODO]

### Entrypoint

To simplify execution of the predefined experiments and visualization of results, the artifact provides an `entrypoint.py` script.

The following experiment identifiers are supported:

0. `demo.toml`
1. `main.toml`
2. `main-12.toml`
3. `chromium-pe-x64.toml`

The index corresponds to the experiment identifier `{exp_id}`.

#### Running Experiments

Run a specific experiment using:

```bash
python3 entrypoint.py exp {exp_id}
```

For example, to run `demo.toml`:

```bash
python3 entrypoint.py exp 0
```

When using Docker, `entrypoint.py` is configured as the container entrypoint. Equivalent arguments can therefore be passed directly to `docker run`:

```bash
docker run -v $(pwd)/eval_results:/NSDA/eval_results \
           -v $(pwd)/logs:/NSDA/logs \
           --gpus all --rm -it nsda-ae exp 0
```

#### Visualizing Results

After an experiment completes, a result file will be generated in `./eval_results`.

The same entrypoint can be used to visualize the results:

```bash
python3 entrypoint.py show {exp_id} ./eval_results/exp_{exp_id}_results.json
```

For example, after experiment 0 completes, the result file `./eval_results/exp_0_results.json` can be displayed using:

```bash
python3 entrypoint.py show 0 ./eval_results/exp_0_results.json
```

The same workflow applies when using Docker. Mount a local directory to `/NSDA/eval_results` so that the generated result file persists after the container terminates.

```bash
docker run -v $(pwd)/eval_results:/NSDA/eval_results \
           --gpus all --rm -it nsda-ae \
           show 0 ./eval_results/exp_0_results.json
```

## Questions

If you encounter issues or have questions about using the artifact, please open an issue in the repository.

## Citation

Please cite our paper if you find this artifact useful:

```bibtex
@inproceedings{xiao2026neurosymbolic,
  author = {Xiao, Zhaoqi and Fu, Yeqi and Wijayadi, Lambang Akbar and Liang, Zhenkai and Yin, Heng},
  title = {Neurosymbolic Disassembly},
  year = {2026},
  month = {November},
  publisher = {Association for Computing Machinery},
  address = {New York, NY, USA},
  booktitle = {Proceedings of the 2026 ACM SIGSAC Conference on Computer and Communications Security},
  location = {The Hague, Netherlands},
  series = {CCS '26},
  note = {To appear}
}
```
