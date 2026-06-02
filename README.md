# NSDA - AE Package

*NSDA AE Package* is for the artifact evaluation of paper *Neurosymbolic Disassembly*. This package contains necessary source code, configuration files and datasets to reproduce the results in the evaluation. 

## Hardware Requirements

This experiment can be only finished on x86_64 architecture. Common commercial PC or server is satisfactory. A GPU is preferred while not required. Any GPU with the memory higher than 8 GB is good. 

## Software Requirements

Any Linux distribution with support of Docker deamon if you want to evaluate in docker container. 

Our local environments are:

* Ubuntu 22.04.5 LTS
* Python 3.12.2
* Ghidra 11.3.2 (Legacy API) & Ghidra 12.0.4

## TL; DR

*This section is for the ones plan to use Docker environment.*

A general usage computer with 2-cores CPU, 64 GB or larger memory, 20 GB free disk. A GPU with 8 GB or larger memory is required. A docker deamon is required. 

1. Build the docker image:
```bash
$ 
```

## Environment Description

We provide two different environments for running the experiment:
1. Ghidra 11.3.2 w/ old pyghidra API described in `requirements-legacy.txt`. This provides the legacy API of pyghidra and will be deprecated in the future. However, as Ghidra 11.3.2 only supports legacy APIs, which is our initial experiment environment for *NSDA*, we use this as default. 
2. Ghidra 12.0.4 w/ new pyghidra API described in `requirements.txt`. These new APIs provide more flexible ways to process binaries with Ghidra. 

## How to run it

We provide two ways to run the artifact: (1) Docker (2) Native Python Virtual Environment. We suggest using the method (1), while we also provide concrete steps to run on your local host machine. 

### Docker

There are two versions of Dockerfile, which are identical except for the Ghidra version and python dependecies of pyghidra as decribed in [environment description](#environment-description). 

1. Default `Dockerfile`: Ghidra 11.3.2 w/ old pyghidra API installed by `requirements-legacy.txt`. 
2. Optional `Dockerfile-12`: Ghidra 12.0.4 w/ new pyghidra API installed by `requirements.txt`. 

To build the docker image for Ghidra 11 w/ legacy API:

```bash
docker build 
```

for Ghidra 12 w/ new API:

```bash
docker build
```

Afterwards, this docker image can be used for running the experiments. To notice, we use two directory in the container to store important information of the experiment. We suggest mounting them as external directory so that you can re-access them after the docker container is terminated. 

* `/NSDA/logs`: Storing the logs of the experiments. Mount this if you want to check the log or progress. 
* `/NSDA/eval_results`: Storing the evaluation results. **Mount this** if you want to keep the evaluation results after the experiments or visualizing the results. 

### Local Environment

We suggest to use a python virtual environment (e.g., condo) for installing the requirements of *NSDA* and running the experiment. 

You need to [install Ghidra and corresponding dependencies (e.g., JRE or JDK) first](https://github.com/nationalsecurityagency/ghidra#install). 

Install requirements for NSDA, for legacy APIs (Ghidra version < 12):
```bash
pip install -r ./requirements-legacy.txt
```

for new APIs (Ghidra version >= 12):
```bash
pip install -r ./requirements.txt
```

### Run Experiments

#### Pre-Configurations

We prepared some pre-configured experiments in the directory `./configs`. Most of them should be finished in the legacy environment. 

* `demo.toml` (legacy API): A demo to test the environment. [Time: TODO]
* `main.toml` (legacy API): All experiments shown in Table 4 and Figure 2. This is the predominant experiment. [time: TODO]
* Sub-experiments of `main.toml` (legacy API): 
   1. `coreutils-arm32-gcc.toml`
   2. `coreutils-arm32-llvm.toml`
   3. `coreutils-mips-gcc.toml`
   4. `coreutils-mips-llvm.toml`
   5. `loadstar-plc.toml`
   6. `openssl-x64.toml`
* `chromium-pe-x64.toml` (new API): The experiment of *Segmented NSDA* on Chromium. 

#### Entrypoint

For easy-start an core experiments and show the results, we prepare an `entrypoint.py` script for starting pre-configured experiments. The supported experiments are listed below:

0. `demo.toml`
1. `main.toml`
2. `main-12.toml`
3. `chrmium-pe-x64.toml`

where the index number is the experiment number `{exp_id}`. 

##### Running Experiments

You can run specified experiments using command below:

```bash
python3 entrypoint.py exp {exp_id}
```

For example, for running `demo.toml`:

```bash
python3 entrypoint.py exp 0
```

If you are using docker, this `entrypoint.sh` script is used as default entrypoint of the docker image, you can simply attach similar arguments to the docker run command:

```bash
docker run --rm --gpus all -v ${HOST_RESULTS_DIR}:/NSDA/eval_results nsda-ae exp {exp_id}
```

##### Visualize Results

After the experiment finishes, a result file will be created under `./eval_results`. You can use the entrypoint to visualize the results as well:

```bash
python3 entrypoint.sh show {exp_id} ./eval_results/exp_{exp_id}_results.json
```

For example, result file `./eval_results/exp_0_results.json` will be created after you finish the experiment 0. You can check the result using:

```bash
python3 entrypoint.sh show 0 ./eval_results/exp_0_results.json
```

Similar usage for docker container. However, you should mount local directory to `/NSDA/eval_results` to persistent the result file. 

```bash
$ docker run --rm --gpus all -v /tmp/nsda_results:/NSDA/eval_results nsda-ae exp 0
$ docker run --rm --gpus all -v /tmp/nsda_results:/NSDA/eval_results nsda-ae show 0 ./eval_results/exp_0_results.json
```

## Questions

Issues are welcome if you find questions in using this package. 

## Citation

Please cite our paper if found this useful:

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