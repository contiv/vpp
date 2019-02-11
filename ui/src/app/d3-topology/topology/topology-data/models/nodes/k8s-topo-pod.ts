import { NodeDataModel } from '../node-data-model';
import { NodeData } from '../../interfaces/node-data';

export class K8sTopoPod extends NodeDataModel implements NodeData {

  constructor(data?: NodeData) {
    super(data);
  }
}
