#!/bin/sh

scp ./bin/libvirt-actuator libvirtactuator:/.
# https://libvirt.org/remote.html
ssh libvirtactuator "/libvirt-actuator bootstrap --manifests /examples --libvirt-uri qemu:///system --in-cluster-libvirt-uri \"qemu+ssh://root@147.75.72.249/system?no_verify=1&keyfile=/root/.ssh/libvirt.pem/privatekey\" --libvirt-private-key=/packet_id_rsa"
