import { K8sNodeModel } from '../models/k8s/k8s-node-model';
import { K8sPodModel } from '../models/k8s/k8s-pod-model';
import { VppInterfaceModel } from '../models/vpp/vpp-interface-model';
import { VppIpamModel } from '../models/vpp/vpp-ipam-model';
import { VppBdModel } from '../models/vpp/vpp-bd-model';

export interface ContivNodeData {
  node: K8sNodeModel;
  vswitch: K8sPodModel;
  pods: K8sPodModel[];
  vppPods: K8sPodModel[];
  interfaces: VppInterfaceModel[];
  ipam: VppIpamModel;
  bd: VppBdModel[];
}
