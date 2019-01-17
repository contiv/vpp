import { EdgeDataModel } from '../../d3-topology/topology/topology-data/models/edge-data-model';
import { TopologyType } from './topology-type';

export interface SpLinkItem {
  link: EdgeDataModel;
  linkType: 'vppLink' | 'vxtunnel';
  topology: TopologyType;
}
