# What is this?

Tower/AWX uses an Execution Environment. This is a Docker container used to run
the playbook/job. This is where a playbook gets its Python interpreter and modules.
This is where the KSM Python SDK is installed.

First install the Ansible EE builder.
```shell
pip install ansible-builder
```
Build the Docker image
```shell
$ ansible-builder build \
  --tag docker.io/keepersecurity/keeper-secrets-manager-tower-ee:latest \
  --context ./context \
  --container-runtime docker
```
Then push to Docker Hub

```shell
$ docker push docker.io/keepersecurity/keeper-secrets-manager-tower-ee:latest
```

