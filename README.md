<h1 align="center">Agent Zap</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_zap">
<img src="https://img.shields.io/github/stars/ostorlab/agent_zap">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_zap is a popular web security scanner supported by the OWASP._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_zap/blob/main/images/logo.png" alt="agent-zap" />
</p>

This repository is an implementation of [Ostorlab Agent](https://pypi.org/project/ostorlab/) for the [zap Fingerprinter](https://github.com/urbanadventurer/zap.git).

## Getting Started
To perform your first scan, simply run the following command.
```shell
ostorlab scan run --install --agent agent/ostorlab/zap domain-name tesla.com
```

This command will download and install `agent/ostorlab/zap`.
For more information, please refer to the [Ostorlab Documentation](https://github.com/Ostorlab/ostorlab/blob/main/README.md)


## Usage

Agent zap can be installed directly from the ostorlab agent store or built from this repository.

 ### Install directly from ostorlab agent store

 ```shell
 ostorlab agent install agent/ostorlab/zap
 ```

You can then run the agent with the following command:

```shell
ostorlab scan run --agent agent/ostorlab/zap domain-name tesla.com
```


### Build directly from the repository

 1. To build the zap agent you need to have [ostorlab](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed ostorlab, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_zap.git && cd agent_zap
```

 3. Build the agent image using ostorlab cli.

 ```shell
 ostortlab agent build --file=ostorlab.yaml --force
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 1. Run the agent using on of the following commands:
	 * If you did not specify an organization when building the image:
	  ```shell
	  ostorlab scan run --agent agent//zap domain-name tesla.com
	  ```
	 * If you specified an organization when building the image:
	  ```shell
	  ostorlab scan run --agent agent/[ORGANIZATION]/zap domain-name tesla.com
	  ```


<p align="center">
<img src="https://github.com/Ostorlab/agent_zap/blob/main/images/zap_vulnz_list.png" alt="agent-zap-vulnz-list" />
</p>

<p align="center">
<img src="https://github.com/Ostorlab/agent_zap/blob/main/images/zap_vulnz_describe.png" alt="agent-zap-vulnz-describe" />
</p>
 

## License
[Apache-2](./LICENSE)


