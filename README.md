# Fafnir

<div align="center">
<img src="./assets/logo/fafnir-logo.png" alt="Logo Fafnir" width="250"/>

<br/>

[Fafnir](#what-is-fafnir)
**·**
[Install](#installation)
**·**
[Usage](#usage)
**·**
[Security Tools](#security-tools)
**·**
[Architecture](#architecture)
**·**
[FaQ](#faq)

</div>

## What is Fafnir?

**Fafnir** is an open-source tool that allows for the complete automation of launching different security tools against an application's code to identify potential vulnerabilities. 

> Fafnir was a dwarf-like creature in Norse mythology, who transformed himself into a terrifying dragon to protect his treasure. [More about his history](https://vikingr.org/other-beings/fafnir)

* Official documentation: TO DO

## Installation

TO DO

## Usage

TO DO

## Security tools

### Integrated

|Tool|Tipology|Status|
|----|--------|------|
|Semgrep|SAST|Integrated|
|Bandit|SAST|Integrated|
|Gitleaks|Secrets Scanning|Integrated|
|osv-scanner|SCA|Integrated|
|Trivy|SCA|Integrated|
|Trivy|Container Security Scan|Integrated|
|Checkov|IaC Scan|Integrated|

### In roadmap

|Tool|Tipology|Status|
|----|--------|------|
|Nuclei|DAST|TO DO|
|Brakeman|SAST|TO DO|
|Lunasec|SAST|TO DO|
|Insider|SAST|TO DO|
|Syft|SBOM generator|TO DO|


## Architecture

TO DO

## FAQ

### docker.errors.DockerException: Error while fetching server API version: ('Connection aborted.', PermissionError(13, 'Permission denied'))

```bash
sudo chmod 666 /var/run/docker.sock
```

### Run slow

First execution pull all images
