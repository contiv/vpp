import { EdgeData } from '../interfaces/edge-data';
import { NodeDataModel } from './node-data-model';
import { Colors } from 'src/app/d3-topology/shared/constants/colors';

export class EdgeDataModel implements EdgeData {
  public id: string;
  public from: string;
  public to: string;
  public source: string;
  public target: string;
  public fromNodeObj: NodeDataModel;
  public toNodeObj: NodeDataModel;
  public color: string;
  public width: string;
  public clickable = true;
  public isDashed = false;
  public type: 'node' | 'vxlan';
  public fromType: 'node' | 'vxlan';
  public toType: 'node' | 'vxlan';

  constructor(data?: EdgeData) {
    this.init();

    if (data) {
      this.setData(data);
    }
  }

  private init() {
    this.id = '';
    this.from = '';
    this.to = '';
    this.fromNodeObj = null;
    this.toNodeObj = null;
    this.color = Colors.LINK_COLOR;
    this.width = '2px';
    this.clickable = true;
    this.isDashed = false;
  }

  public setData(data: EdgeData): void {
    Object.keys(data).forEach(
      key => {
        this[key] = data[key];
      }
    );

    this.source = this.from;
    this.target = this.to;
  }

  public setLinkColor(color: string) {
    this.color = color;
  }

  public setDashed(state: boolean) {
    this.isDashed = state;
  }

  public setClickable(state: boolean) {
    this.clickable = state;
  }

  public swapFromToNodes() {
    const fromId = this.from;
    const fromNode = this.fromNodeObj;

    this.from = this.to;
    this.fromNodeObj = this.toNodeObj;

    this.to = fromId;
    this.toNodeObj = fromNode;
  }

}
