import { VppInterfaceModel } from '../models/vpp/vpp-interface-model';

export interface VswitchInterfaceList {
  title: string;
  interfaces: VppInterfaceModel[];
}
