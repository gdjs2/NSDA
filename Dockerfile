# Use a newer official CUDA runtime image while keeping Ubuntu 22.04
FROM nvidia/cuda:13.1.2-cudnn-devel-ubuntu22.04

# Avoid interactive apt/tzdata prompts during docker build
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Etc/UTC

# Install system dependencies required for pyenv and project libraries
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		tzdata \
		ca-certificates \
		curl \
		git \
		wget \
		unzip \
		gcc \
		make \
		graphviz \
		libgraphviz-dev \
		libopenblas-dev \
		liblapack-dev \
		libjpeg-dev \
		libpng-dev \
		libtiff-dev \
		libfreetype6-dev \
		libbz2-dev \
		libffi-dev \
		libssl-dev \
		libsqlite3-dev \
		xz-utils \
		liblzma-dev \
		tk-dev \
		libncurses5-dev \
		libreadline-dev \
		zlib1g-dev \
	&& ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
	&& echo $TZ > /etc/timezone \
	&& rm -rf /var/lib/apt/lists/*

# Build and install radare2 from the upstream repository
RUN git clone https://github.com/radareorg/radare2 /opt/radare2 \
	&& /opt/radare2/sys/install.sh

ENV PYENV_ROOT=/opt/pyenv
ENV PATH="$PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH"
ENV PYTHON_VERSION=3.12.10

# Install pyenv and pyenv-virtualenv
RUN git clone https://github.com/pyenv/pyenv.git "$PYENV_ROOT" \
	&& git clone https://github.com/pyenv/pyenv-virtualenv.git "$PYENV_ROOT/plugins/pyenv-virtualenv" \
	&& printf '%s\n' \
		'export PYENV_ROOT=/opt/pyenv' \
		'export PATH="$PYENV_ROOT/bin:$PYENV_ROOT/shims:$PATH"' \
		'eval "$(pyenv init -)"' \
		'eval "$(pyenv virtualenv-init -)"' \
		> /etc/profile.d/pyenv.sh \
	&& chmod 644 /etc/profile.d/pyenv.sh \
	&& printf '%s\n' \
		'if [ -f /etc/profile.d/pyenv.sh ]; then . /etc/profile.d/pyenv.sh; fi' \
		>> /root/.bashrc

# Set working directory
WORKDIR /NSDA

# Copy requirement files into /tmp as requested
COPY requirements.txt /tmp/requirements.txt
COPY requirements-legacy.txt /tmp/requirements-legacy.txt

# Create two Python 3.12 pyenv virtual environments and install dependencies
RUN bash -lc ' \
	eval "$(pyenv init -)" && \
	eval "$(pyenv virtualenv-init -)" && \
	pyenv install -s "$PYTHON_VERSION" && \
	pyenv virtualenv -f "$PYTHON_VERSION" nsda && \
	pyenv virtualenv -f "$PYTHON_VERSION" nsda-legacy && \
	PYENV_VERSION=nsda pyenv exec python -m pip install --upgrade pip setuptools wheel && \
	PYENV_VERSION=nsda pyenv exec pip install --no-cache-dir -r /tmp/requirements.txt && \
	PYENV_VERSION=nsda-legacy pyenv exec python -m pip install --upgrade pip setuptools wheel && \
	PYENV_VERSION=nsda-legacy pyenv exec pip install --no-cache-dir -r /tmp/requirements-legacy.txt \
'

# Download and extract OpenJDK 21
RUN wget -O /tmp/jdk-21.0.7_linux-x64_bin.tar.gz https://download.oracle.com/java/21/archive/jdk-21.0.7_linux-x64_bin.tar.gz \
	&& mkdir -p /opt/jdk-21 \
	&& tar -xzf /tmp/jdk-21.0.7_linux-x64_bin.tar.gz -C /opt/jdk-21 --strip-components=1 \
	&& rm /tmp/jdk-21.0.7_linux-x64_bin.tar.gz

ENV JAVA_HOME=/opt/jdk-21
ENV PATH="$JAVA_HOME/bin:$PATH"

# Download and extract Ghidra 11.3.2
RUN wget -O /tmp/ghidra_11.3.2_PUBLIC_20250415.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip \
	&& unzip /tmp/ghidra_11.3.2_PUBLIC_20250415.zip -d /opt \
	&& rm /tmp/ghidra_11.3.2_PUBLIC_20250415.zip

# Download and extract Ghidra 12.0.4
RUN wget -O /tmp/ghidra_12.0.4_PUBLIC_20260303.zip https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip \
	&& unzip /tmp/ghidra_12.0.4_PUBLIC_20260303.zip -d /opt \
	&& rm /tmp/ghidra_12.0.4_PUBLIC_20260303.zip

ENV GHIDRA_11_INSTALL_DIR=/opt/ghidra_11.3.2_PUBLIC
ENV GHIDRA_12_INSTALL_DIR=/opt/ghidra_12.0.4_PUBLIC
ENV GHIDRA_INSTALL_DIR=$GHIDRA_11_INSTALL_DIR

# Copy datasets
COPY Datasets /NSDA/Datasets

# Download Models for Loadstar
RUN wget -O /NSDA/Datasets/Loadstar/new_weights.weights.h5 https://huggingface.co/benksy/itr_ns1/resolve/main/new_weights.weights.h5?download=true

# Copy source code
COPY src /NSDA/src

# Copy config files
COPY configs /NSDA/configs

CMD ["bash", "-l"]
