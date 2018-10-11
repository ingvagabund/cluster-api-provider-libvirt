# Libvirt actuator

The command allows to directly interact with the libvirt actuator.

## How to prepare environment

For running the libvirt actuator with Fedora 28 Cloud images.

1. Provision instance in `packet.net`:
   ```sh
   $ ./hack/packet-provision.sh install
   ```
   and get the IP address (assuming it is `147.75.96.139`).

1. Update ``~/.ssh/config`` to contain:
   ```
   Host libvirtactuator 147.75.96.139
   Hostname 147.75.96.139
   User root
   StrictHostKeyChecking no
   PasswordAuthentication no
   UserKnownHostsFile ~/.ssh/aws_known_hosts
   IdentityFile /tmp/packet_id_rsa
   IdentitiesOnly yes
   Compression yes
   ```

1. Run [init script](resources/init.sh) to:
   - update qemu-kvm to at least 2.4
   - create default volume storage
   - create cloud init volume
   - create `fedora_base` volume

   ```sh
   $ bash cmd/libvirt-actuator/resources/init.sh
   ```

   In case the default [cloud-init](resources/user-data) is not sufficient,
   you can generate new `cloud-init.iso` with the following steps:

   1. Update content of [meta-data](resources/meta-data) file (the filename must be `meta-data`)
   1. Update content of [user-data](resources/user-data) (the filename must be `user-data`)
   1. Generate new iso with the cloud init by running:
      ```sh
      $ genisoimage -output cloud-init.iso -volid cidata -joliet -r user-data meta-data
      ```
   1. Upload the iso to the instance in case you already run the `init.sh` script:
      ```
      $ scp cloud-init.iso libvirtactuator:/var/lib/libvirt/images/cloud-init.iso
      ```

   *WARNING*: Please keep the `/sys/firmware/qemu_fw_cfg/by_name/opt/actuator.libvirt.io.k8s.sigs/config/raw` path
   in the `user-data` file as it is. Otherwise, the user data (see below)
   provided by kubernetes secret will get ignored.

## How to prepare machine resources

By default, available user data (under [user-data.sh](resources/user-data.sh) file)
contains a shell script that deploys kubernetes master node.
Feel free to modify the file to your needs.

The libvirt actuator expectes the user data to be provided by a kubernetes secret
by setting `spec.providerConfig.value.cloudInit.userDataSecret` field.
See [userdata.yml](resources/userdata.yml) for example.

At the same time, the `spec.providerConfig.value.uri` needs to be set to libvirt
uri. E.g. `qemu+ssh://root@147.75.96.139/system` in case the libivrt instance
is accessible via ssh on `147.75.96.139` IP address.

## To build the `libvirt-actuator` binary:

You'll need to install `libvirt-dev[el]` installed on the system you are building and running the binary.
e.g. `apt-get -y install libvirt-dev` or `yum -y install libvirt-devel`

```sh
CGO_ENABLED=1 go build -o bin/libvirt-actuator -a github.com/openshift/cluster-api-provider-libvirt/cmd/libvirt-actuator
```

### Create libvirt instance based on machine manifest

```sh
$ ./bin/libvirt-actuator create -m examples/machine.yaml -c examples/cluster.yaml
```

Once the libvirt instance is created you can login inside (username: `fedora`, password: `fedora`):
```
$ virsh -c qemu+ssh://root@147.75.96.139/system console
```

Meantime you can check `/root/user-data.logs` to see the progress of deploying kubernetes master node:
```
$ watch -n 1 sudo tail -20 /root/user-data.logs
```

Once the deployment is done, you can list the master node:

```
$ sudo kubectl get nodes
NAME                   STATUS    ROLES     AGE       VERSION
fedora.example.local   Ready     master    17m       v1.11.3
```

#### How run the `kubectl get nodes` from your laptop

1. Get private ip address of the master node (e.g. `192.168.122.6`)
1. Tunnel to the master guest (port `22` for pulling the kubeconfig, port `8443` for querying apiserver):
   ```sh
   $ sudo ssh -L 8443:192.168.122.51:8443 -L 22:192.168.122.51:22 -i /tmp/packet_id_rsa root@147.75.96.109
   ```
1. Pull kubeconfig from the master guest node:
   ```sh
   $ ssh -i cmd/libvirt-actuator/resources/guest.pem fedora@127.0.0.1 'sudo cat /etc/kubernetes/admin.conf' > kubeconfig
   ```
1. Modify the kubeconfig:
   ```sh
   $ export KUBECONFIG=$PWD/kubeconfig
   $ kubectl config set-cluster kubernetes --server=https://127.0.0.1:8443
   ```
1. List nodes:
   ```sh
   $ kubectl get nodes
   NAME             STATUS    ROLES     AGE       VERSION
   192.168.122.51   Ready     master    14m       v1.11.3
   ```

### Test if libvirt instance exists based on machine manifest

```sh
$ ./bin/libvirt-actuator exists -m examples/machine.yaml -c examples/cluster.yaml
```

### Delete libvirt instance based on machine manifest

```sh
$ ./bin/libvirt-actuator delete -m examples/machine.yaml -c examples/cluster.yaml
```
