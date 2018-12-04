import { NodeData } from '../interfaces/node-data';
import { TopologyType } from '../../interfaces/topology-type';
import { Colors } from 'src/app/d3-topology/shared/constants/colors';
import { Sizes } from 'src/app/d3-topology/shared/constants/sizes';
import { NodeType } from '../interfaces/node-type';

export abstract class NodeDataModel implements NodeData {
  public id: string;
  public label: string;
  public labelColor: string;
  public icon: string;
  public iconWidth: number;
  public iconHeight: number;
  public x: number;
  public y: number;
  public type: TopologyType;
  public stroke: string;
  public strokeWidth: string;
  public nodeType: NodeType;

  public IP: string;
  public namespace: string;

  constructor(data?: NodeData) {
    this.init();

    if (data) {
      this.setData(data);
    }
  }

  private init() {
    this.id = '';
    this.label = '';
    this.labelColor = Colors.LABEL_COLOR;
    this.icon = '';
    this.iconWidth = 0;
    this.iconHeight = 0;
    this.x = 0;
    this.y = 0;
    this.type = 'topology-item';
    this.stroke = Colors.NODE_STROKE;
    this.strokeWidth = Sizes.CIRCLE_STROKE_WIDTH;
    this.nodeType = 'node';

    this.IP = '';
    this.namespace = '';
  }

  public setData(data: NodeData): void {
    Object.keys(data).forEach(
      key => {
        this[key] = data[key];
      }
    );
  }

}
