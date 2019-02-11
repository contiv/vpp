import { EdgeDataModel } from '../../topology-data/models/edge-data-model';

export interface LinkClickEvent {
  link: EdgeDataModel;
  svgLink: any;
}
