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

## How to run it

We provide two ways to run the artifact: (1) Docker (2) Native Python Virtual Environment. We suggest using the method (1), while we also provide concrete steps to run on your local host machine. 

### Docker

We have built a docker image on [TODO] using the Dockerfile in the project's root directory. 