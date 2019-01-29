import { Injectable } from '@angular/core';
import { CoreService } from '../shared/core.service';
import { SvgTransform } from '../topology/interfaces/svg-transform';

@Injectable({
  providedIn: 'root'
})
export class TopologyVizService {

  private svgObject: d3.Selection<SVGSVGElement, {}, null, undefined>;
  private zoomBeh: d3.ZoomBehavior<SVGSVGElement, any>;

  constructor(
    private coreService: CoreService
  ) { }

  public getSvgTransform(): SvgTransform {
    return this.coreService.parseTransform(this.svgObject.select('.content').attr('transform'));
  }

    /**
   * Set d3.svg to local property
   */
  public setSvgObject(svgObject: any) {
    this.svgObject = svgObject;
  }

  /**
   * Return d3.svg object for use
   */
  public getSvgObject() {
    return this.svgObject;
  }

  public setZoomBeh(zoom: d3.ZoomBehavior<SVGSVGElement, any>) {
    this.zoomBeh = zoom;
  }

  public getZoomBeh(): d3.ZoomBehavior<SVGSVGElement, any> {
    return this.zoomBeh;
  }
}
