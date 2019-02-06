import { TopologyType } from '../../interfaces/topology-type';
import { NodeType } from './node-type';

export interface NodeData {
  id: string;
  label?: string;
  labelColor?: string;
  icon?: string;
  iconWidth?: number;
  iconHeight?: number;
  x: number;
  y: number;
  type?: TopologyType;
  stroke?: string;
  strokeWidth?: string;
  nodeType: NodeType;

  IP?: string;
  namespace?: string;
}
