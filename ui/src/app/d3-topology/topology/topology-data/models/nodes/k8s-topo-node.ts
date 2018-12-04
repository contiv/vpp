import { NodeDataModel } from '../node-data-model';
import { NodeData } from '../../interfaces/node-data';

export class K8sTopoNode extends NodeDataModel implements NodeData {

  constructor(data?: NodeData) {
    super(data);
  }
}
