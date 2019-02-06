import { NodeDataModel } from '../../topology-data/models/node-data-model';

export interface EdgeData {
  id: string;
  from: string;
  to: string;
  fromNodeObj?: NodeDataModel;
  toNodeObj?: NodeDataModel;
  color?: string;
  width?: string;
  clickable?: boolean;
  isDashed?: boolean;
  type: 'node' | 'vxlan';
  fromType: 'node' | 'vxlan';
  toType: 'node' | 'vxlan';
}
