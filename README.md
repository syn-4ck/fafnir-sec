# Fafnir

## What is Fafnir?

**Fafnir** is an open-source tool that allows for the complete automation of launching different security tools against an application's code to identify potential vulnerabilities. 

> Fafnir was a dwarf-like creature in Norse mythology, who transformed himself into a terrifying dragon to protect his treasure. [More about his history](https://vikingr.org/other-beings/fafnir)

## Security tools integrated

|Tool|Tipology|Status|
|----|--------|------|
|Semgrep|SAST|Integrated|
|Gitleaks|Secrets Scanning|Integrated|
|Dependency-check|SCA|Integrated|
|Trivy|Container Security Scan|Integrated|
|Nuclei|DAST|TO DO|

## Architecture

TO DO

## FAQ

### docker.errors.DockerException: Error while fetching server API version: ('Connection aborted.', PermissionError(13, 'Permission denied'))

```bash
sudo chmod 666 /var/run/docker.sock
```

### Run slow

First execution pull all images
