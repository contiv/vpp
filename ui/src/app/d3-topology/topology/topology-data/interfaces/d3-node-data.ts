import { NodeDataModel } from '../models/node-data-model';

export interface D3NodeData {
  shape?: string;
  node?: NodeDataModel;
  attrs?: {
    [prop: string]: any;
  };
  D3Node?: D3NodeData;
}
