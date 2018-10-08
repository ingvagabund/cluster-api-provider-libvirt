/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

// Tests individual Libvirt actuator actions

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/openshift/cluster-api-provider-libvirt/cmd/libvirt-actuator/utils"

	"github.com/golang/glog"
	"github.com/kubernetes-incubator/apiserver-builder/pkg/controller"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/apimachinery/pkg/util/wait"
	clusterv1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"

	"github.com/ghodss/yaml"

	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/cluster-api/pkg/client/clientset_generated/clientset"
)

const (
	pollInterval        = 5 * time.Second
	timeoutPoolInterval = 20 * time.Minute
)

func usage() {
	fmt.Printf("Usage: %s\n\n", os.Args[0])
}

var rootCmd = &cobra.Command{
	Use:   "libvirt-actuator-test",
	Short: "Test for Cluster API Libvirt actuator",
}

func createCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "create",
		Short: "Create machine instance for specified cluster",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFlags(cmd); err != nil {
				return err
			}
			cluster, machine, userData, err := utils.ReadClusterResources(
				cmd.Flag("cluster").Value.String(),
				cmd.Flag("machine").Value.String(),
				cmd.Flag("userdata").Value.String(),
			)
			if err != nil {
				return err
			}

			actuator := utils.CreateActuator(machine, userData, log.WithField("example", "create-machine"))
			err = actuator.Create(cluster, machine)
			if err != nil {
				return err
			}
			fmt.Printf("Machine creation was successful!\n")
			return nil
		},
	}
}

func deleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete INSTANCE-ID",
		Short: "Delete machine instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFlags(cmd); err != nil {
				return err
			}

			cluster, machine, userData, err := utils.ReadClusterResources(
				cmd.Flag("cluster").Value.String(),
				cmd.Flag("machine").Value.String(),
				cmd.Flag("userdata").Value.String(),
			)
			if err != nil {
				return err
			}

			actuator := utils.CreateActuator(machine, userData, log.WithField("example", "create-machine"))
			err = actuator.Delete(cluster, machine)
			if err != nil {
				return err
			}
			fmt.Printf("Machine delete operation was successful.\n")
			return nil
		},
	}
}

func existsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "exists",
		Short: "Determine if underlying machine instance exists",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := checkFlags(cmd); err != nil {
				return err
			}

			cluster, machine, userData, err := utils.ReadClusterResources(
				cmd.Flag("cluster").Value.String(),
				cmd.Flag("machine").Value.String(),
				cmd.Flag("userdata").Value.String(),
			)
			if err != nil {
				return err
			}

			actuator := utils.CreateActuator(machine, userData, log.WithField("example", "create-machine"))
			exists, err := actuator.Exists(cluster, machine)
			if err != nil {
				return err
			}
			if exists {
				fmt.Printf("Underlying machine's instance exists.\n")
			} else {
				fmt.Printf("Underlying machine's instance not found.\n")
			}
			return nil
		},
	}
}

func readClusterManifest(manifestLoc string) (*clusterv1.Cluster, error) {
	cluster := &clusterv1.Cluster{}
	bytes, err := ioutil.ReadFile(manifestLoc)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %v", manifestLoc, err)
	}

	if err = yaml.Unmarshal(bytes, &cluster); err != nil {
		return nil, fmt.Errorf("unable to unmarshal %v: %v", manifestLoc, err)
	}

	return cluster, nil
}

type manifestParams struct {
	ClusterID  string
	LibvirtURI string
}

func readMachineManifest(manifestParams *manifestParams, manifestLoc string) (*clusterv1.Machine, error) {
	machine := &clusterv1.Machine{}
	manifestBytes, err := ioutil.ReadFile(manifestLoc)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %v", manifestLoc, err)
	}

	t, err := template.New("machineuserdata").Parse(string(manifestBytes))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, *manifestParams)
	if err != nil {
		return nil, err
	}

	if err = yaml.Unmarshal(buf.Bytes(), &machine); err != nil {
		return nil, fmt.Errorf("unable to unmarshal %v: %v", manifestLoc, err)
	}

	return machine, nil
}

func readSecretManifest(manifestLoc string) (*apiv1.Secret, error) {
	secret := &apiv1.Secret{}
	bytes, err := ioutil.ReadFile(manifestLoc)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %v", manifestLoc, err)
	}
	if err = yaml.Unmarshal(bytes, &secret); err != nil {
		return nil, fmt.Errorf("unable to unmarshal %v: %v", manifestLoc, err)
	}
	return secret, nil
}

func cmdRun(binaryPath string, args ...string) ([]byte, error) {
	cmd := exec.Command(binaryPath, args...)
	return cmd.CombinedOutput()
}

type TestConfig struct {
	KubeClient *kubernetes.Clientset
	CAPIClient *clientset.Clientset
}

func createNamespace(testConfig *TestConfig, namespace string) error {
	nsObj := &apiv1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}

	log.Infof("Creating %q namespace...", nsObj.Name)
	if _, err := testConfig.KubeClient.CoreV1().Namespaces().Get(nsObj.Name, metav1.GetOptions{}); err != nil {
		if _, err := testConfig.KubeClient.CoreV1().Namespaces().Create(nsObj); err != nil {
			return fmt.Errorf("unable to create namespace: %v", err)
		}
	}

	return nil
}

func createCluster(testConfig *TestConfig, cluster *clusterv1.Cluster) error {
	log.Infof("Creating %q cluster...", strings.Join([]string{cluster.Namespace, cluster.Name}, "/"))
	if _, err := testConfig.CAPIClient.ClusterV1alpha1().Clusters(cluster.Namespace).Get(cluster.Name, metav1.GetOptions{}); err != nil {
		if _, err := testConfig.CAPIClient.ClusterV1alpha1().Clusters(cluster.Namespace).Create(cluster); err != nil {
			return fmt.Errorf("unable to create cluster: %v", err)
		}
	}

	return nil
}

func createMachineSet(testConfig *TestConfig, machineset *clusterv1.MachineSet) error {
	log.Infof("Creating %q machineset...", strings.Join([]string{machineset.Namespace, machineset.Name}, "/"))
	if _, err := testConfig.CAPIClient.ClusterV1alpha1().MachineSets(machineset.Namespace).Get(machineset.Name, metav1.GetOptions{}); err != nil {
		if _, err := testConfig.CAPIClient.ClusterV1alpha1().MachineSets(machineset.Namespace).Create(machineset); err != nil {
			return fmt.Errorf("unable to create machineset: %v", err)
		}
	}

	return nil
}

const workerUserDataBlob = `#!/bin/bash

cat <<HEREDOC > /root/user-data.sh
#!/bin/bash

cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
exclude=kube*
EOF
setenforce 0
yum install -y docker
systemctl enable docker
systemctl start docker
yum install -y kubelet-1.11.3 kubeadm-1.11.3 --disableexcludes=kubernetes

cat <<EOF > /etc/default/kubelet
KUBELET_KUBEADM_EXTRA_ARGS=--cgroup-driver=systemd
EOF

kubeadm join {{ .MasterIP }}:8443 --token 2iqzqm.85bs0x6miyx1nm7l --discovery-token-unsafe-skip-ca-verification

HEREDOC

bash /root/user-data.sh > /root/user-data.logs
`

type userDataParams struct {
	MasterIP string
}

func generateWorkerUserData(masterIP string, workerUserDataSecret *apiv1.Secret) (*apiv1.Secret, error) {
	params := userDataParams{
		MasterIP: masterIP,
	}
	t, err := template.New("workeruserdata").Parse(workerUserDataBlob)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, params)
	if err != nil {
		return nil, err
	}

	secret := workerUserDataSecret.DeepCopy()
	secret.Data["userData"] = []byte(buf.String())

	return secret, nil
}

func createSecret(testConfig *TestConfig, secret *apiv1.Secret) error {
	log.Infof("Creating %q secret...", strings.Join([]string{secret.Namespace, secret.Name}, "/"))
	if _, err := testConfig.KubeClient.CoreV1().Secrets(secret.Namespace).Get(secret.Name, metav1.GetOptions{}); err != nil {
		if _, err := testConfig.KubeClient.CoreV1().Secrets(secret.Namespace).Create(secret); err != nil {
			return fmt.Errorf("unable to create secret: %v", err)
		}
	}

	return nil
}

func readMachineSetManifest(manifestParams *manifestParams, manifestLoc string) (*clusterv1.MachineSet, error) {
	machineset := &clusterv1.MachineSet{}
	manifestBytes, err := ioutil.ReadFile(manifestLoc)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %v", manifestLoc, err)
	}

	t, err := template.New("machinesetuserdata").Parse(string(manifestBytes))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = t.Execute(&buf, *manifestParams)
	if err != nil {
		return nil, err
	}

	if err = yaml.Unmarshal(buf.Bytes(), &machineset); err != nil {
		return nil, fmt.Errorf("unable to unmarshal %v: %v", manifestLoc, err)
	}

	return machineset, nil
}

func BuildPKSecret(secretName, namespace, pkLoc string) (*apiv1.Secret, error) {
	pkBytes, err := ioutil.ReadFile(pkLoc)
	if err != nil {
		return nil, fmt.Errorf("unable to read %v: %v", pkLoc, err)
	}

	return &apiv1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			"privatekey": pkBytes,
		},
	}, nil
}

func bootstrapCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Bootstrap kubernetes cluster with kubeadm",
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestsDir := cmd.Flag("manifests").Value.String()
			if manifestsDir == "" {
				return fmt.Errorf("--manifests needs to be set")
			}

			libvirturi := cmd.Flag("libvirt-uri").Value.String()
			if libvirturi == "" {
				return fmt.Errorf("--libvirturi needs to be set")
			}

			inclusterlibvirturi := cmd.Flag("in-cluster-libvirt-uri").Value.String()
			if inclusterlibvirturi == "" {
				return fmt.Errorf("--in-cluster-libvirturi needs to be set")
			}

			libvirtpk := cmd.Flag("libvirt-private-key").Value.String()
			if libvirtpk == "" {
				return fmt.Errorf("--libvirt-private-key needs to be set")
			}

			log.Infof("Creating secret with the libvirt PK from %v", libvirtpk)
			libvirtPKSecret, err := BuildPKSecret("libvirt-private-key", "default", libvirtpk)
			if err != nil {
				return fmt.Errorf("unable to create libvirt-private-key secret: %v", err)
			}

			machinePrefix := cmd.Flag("environment-id").Value.String()

			log.Infof("Reading cluster manifest from %v", path.Join(manifestsDir, "cluster.yaml"))
			cluster, err := readClusterManifest(path.Join(manifestsDir, "cluster.yaml"))
			if err != nil {
				return err
			}

			log.Infof("Reading master machine manifest from %v", path.Join(manifestsDir, "master-machine.yaml"))
			masterMachine, err := readMachineManifest(
				&manifestParams{
					LibvirtURI: libvirturi,
				},
				path.Join(manifestsDir, "master-machine.yaml"),
			)
			if err != nil {
				return err
			}

			log.Infof("Reading master user data manifest from %v", path.Join(manifestsDir, "master-userdata.yaml"))
			masterUserDataSecret, err := readSecretManifest(path.Join(manifestsDir, "master-userdata.yaml"))
			if err != nil {
				return err
			}

			if machinePrefix != "" {
				masterMachine.Name = machinePrefix + "-" + masterMachine.Name
			}

			// fmt.Printf("cluster: %#v\n", cluster)
			// fmt.Printf("masterMachine: %#v\n", masterMachine)
			// fmt.Printf("masterUserDataSecret: %#v\n", masterUserDataSecret)

			log.Infof("Creating master machine")

			actuator := utils.CreateActuator(masterMachine, masterUserDataSecret, log.WithField("example", "create-machine"))
			err = actuator.Create(cluster, masterMachine)
			if err != nil {
				return err
			}

			// Wait until the instance has the ip address
			var masterMachinePrivateIP string
			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Info("Waiting for master machine internal IP")
				libvirtInstance, err := actuator.Describe(cluster, masterMachine)
				if err != nil {
					log.Info(err)
					return false, nil
				}

				if len(libvirtInstance.NodeAddresses) == 0 {
					log.Infof("No node addresses found")
					return false, nil
				}

				for _, address := range libvirtInstance.NodeAddresses {
					if address.Type == apiv1.NodeInternalIP {
						masterMachinePrivateIP = address.Address
						break
					}
				}

				if masterMachinePrivateIP == "" {
					log.Infof("No internal IP address found")
					return false, nil
				}

				return true, nil
			})
			if err != nil {
				return err
			}

			log.Infof("Master machine running at %v", masterMachinePrivateIP)

			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Infof("Pulling kubeconfig from %v:8443", masterMachinePrivateIP)
				output, err := cmdRun("ssh", "-o StrictHostKeyChecking=no", fmt.Sprintf("fedora@%v", masterMachinePrivateIP), "sudo cat /etc/kubernetes/admin.conf")
				if err != nil {
					log.Infof("Unable to pull kubeconfig: %v, %v", err, string(output))
					return false, nil
				}

				f, err := os.Create("kubeconfig")
				if err != nil {
					return false, err
				}

				if _, err = f.Write(output); err != nil {
					f.Close()
					return false, err
				}
				f.Close()

				return true, nil
			})

			// Wait until the cluster comes up
			config, err := controller.GetConfig("kubeconfig")
			if err != nil {
				return fmt.Errorf("unable to create config: %v", err)
			}

			kubeClient, err := kubernetes.NewForConfig(config)
			if err != nil {
				glog.Fatalf("Could not create kubernetes client to talk to the apiserver: %v", err)
			}

			capiclient, err := clientset.NewForConfig(config)
			if err != nil {
				glog.Fatalf("Could not create client for talking to the apiserver: %v", err)
			}

			tc := &TestConfig{
				KubeClient: kubeClient,
				CAPIClient: capiclient,
			}

			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Info("Waiting for all nodes to come up")
				nodesList, err := kubeClient.CoreV1().Nodes().List(metav1.ListOptions{})
				if err != nil {
					return false, nil
				}

				nodesReady := true
				for _, node := range nodesList.Items {
					ready := false
					for _, c := range node.Status.Conditions {
						if c.Type != apiv1.NodeReady {
							continue
						}
						ready = true
					}
					log.Infof("Is node %q ready?: %v\n", node.Name, ready)
					if !ready {
						nodesReady = false
					}
				}

				return nodesReady, nil
			})

			log.Info("Deploying cluster-api stack")
			log.Info("Deploying aws credentials")

			if err := createNamespace(tc, "test"); err != nil {
				return err
			}

			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Info("Deploying cluster-api server")
				if output, err := cmdRun("kubectl", "--kubeconfig=kubeconfig", "apply", fmt.Sprintf("-f=%v", path.Join(manifestsDir, "cluster-api-server.yaml")), "--validate=false"); err != nil {
					log.Infof("Unable to apply %v manifest: %v\n%v", path.Join(manifestsDir, "cluster-api-server.yaml"), err, string(output))
					return false, nil
				}

				return true, nil
			})

			if err := createSecret(tc, libvirtPKSecret); err != nil {
				return err
			}

			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Info("Deploying cluster-api controllers")
				if output, err := cmdRun("kubectl", "--kubeconfig=kubeconfig", "apply", fmt.Sprintf("-f=%v", path.Join(manifestsDir, "provider-components.yml"))); err != nil {
					log.Infof("Unable to apply %v manifest: %v\n%v", path.Join(manifestsDir, "provider-components.yml"), err, string(output))
					return false, nil
				}
				return true, nil
			})

			testCluster := &clusterv1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "tb-asg-35",
					Namespace: "test",
				},
				Spec: clusterv1.ClusterSpec{
					ClusterNetwork: clusterv1.ClusterNetworkingConfig{
						Services: clusterv1.NetworkRanges{
							CIDRBlocks: []string{"10.0.0.1/24"},
						},
						Pods: clusterv1.NetworkRanges{
							CIDRBlocks: []string{"10.0.0.1/24"},
						},
						ServiceDomain: "example.com",
					},
				},
			}

			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Infof("Deploying cluster resource")

				if err := createCluster(tc, testCluster); err != nil {
					log.Infof("Unable to deploy cluster manifest: %v", err)
					return false, nil
				}

				return true, nil
			})

			log.Infof("Reading worker user data manifest from %v", path.Join(manifestsDir, "worker-userdata.yaml"))
			workerUserDataSecret, err := readSecretManifest(path.Join(manifestsDir, "worker-userdata.yaml"))
			if err != nil {
				return err
			}

			log.Infof("Generating worker machine set user data for master listening at %v", masterMachinePrivateIP)
			workerUserDataSecret, err = generateWorkerUserData(masterMachinePrivateIP, workerUserDataSecret)
			if err != nil {
				return fmt.Errorf("unable to generate worker user data: %v", err)
			}

			if err := createSecret(tc, workerUserDataSecret); err != nil {
				return err
			}

			log.Infof("Reading worker machine manifest from %v", path.Join(manifestsDir, "worker-machineset.yaml"))
			workerMachineSet, err := readMachineSetManifest(
				&manifestParams{
					LibvirtURI: inclusterlibvirturi,
				},
				path.Join(manifestsDir, "worker-machineset.yaml"),
			)
			if err != nil {
				return err
			}

			if machinePrefix != "" {
				workerMachineSet.Name = machinePrefix + "-" + workerMachineSet.Name
			}

			err = wait.Poll(pollInterval, timeoutPoolInterval, func() (bool, error) {
				log.Info("Deploying worker machineset")
				if err := createMachineSet(tc, workerMachineSet); err != nil {
					log.Infof("unable to create machineset: %v", err)
					return false, nil
				}

				return true, nil
			})

			return nil
		},
	}

	cmd.PersistentFlags().StringP("manifests", "", "", "Directory with bootstrapping manifests")
	return cmd
}

func init() {
	rootCmd.PersistentFlags().StringP("machine", "m", "", "Machine manifest")
	rootCmd.PersistentFlags().StringP("cluster", "c", "", "Cluster manifest")
	rootCmd.PersistentFlags().StringP("userdata", "u", "", "User data manifest")
	rootCmd.PersistentFlags().StringP("libvirt-uri", "", "", "Libvirt URI. E.g. qemu//system")
	rootCmd.PersistentFlags().StringP("in-cluster-libvirt-uri", "", "", "Libvirt URI for docker container. E.g. qemu+ssh://root@IP/system")
	rootCmd.PersistentFlags().StringP("libvirt-private-key", "", "", "Private key file for libvirt qemu+ssh URI")

	cUser, err := user.Current()
	if err != nil {
		rootCmd.PersistentFlags().StringP("environment-id", "p", "", "Directory with bootstrapping manifests")
	} else {
		rootCmd.PersistentFlags().StringP("environment-id", "p", cUser.Username, "Machine prefix, by default set to the current user")
	}

	rootCmd.AddCommand(createCommand())
	rootCmd.AddCommand(deleteCommand())
	rootCmd.AddCommand(existsCommand())
	rootCmd.AddCommand(bootstrapCommand())
}

func checkFlags(cmd *cobra.Command) error {
	if cmd.Flag("cluster").Value.String() == "" {
		return fmt.Errorf("--%v/-%v flag is required", cmd.Flag("cluster").Name, cmd.Flag("cluster").Shorthand)
	}
	if cmd.Flag("machine").Value.String() == "" {
		return fmt.Errorf("--%v/-%v flag is required", cmd.Flag("machine").Name, cmd.Flag("machine").Shorthand)
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error occurred: %v\n", err)
		os.Exit(1)
	}
}
