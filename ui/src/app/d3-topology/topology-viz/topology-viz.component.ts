import { Component, OnInit, OnDestroy, AfterViewInit, ViewChild, ElementRef, Input, Output, EventEmitter,
  ViewEncapsulation } from '@angular/core';
import { Subscription } from 'rxjs';
import { CoreService } from '../shared/core.service';
import { TopologyService } from '../topology/topology.service';
import { TopologyVizService } from './topology-viz.service';
import { NodeDataModel } from '../topology/topology-data/models/node-data-model';
import { EdgeDataModel } from '../topology/topology-data/models/edge-data-model';
import { NodeClickEvent } from '../topology/interfaces/events/node-click-event';
import { LinkClickEvent } from '../topology/interfaces/events/link-click-event';
import { SvgTransform } from '../topology/interfaces/svg-transform';
import { RenderOptions } from '../topology/interfaces/render-options';
import { VppTopoVswitch } from '../topology/topology-data/models/nodes/vpp-topo-vswitch';
import { VppTopoBvi } from '../topology/topology-data/models/nodes/vpp-topo-bvi';

import * as d3 from 'd3';
import { K8sTopoNode } from '../topology/topology-data/models/nodes/k8s-topo-node';
import { TopologyDataModel } from '../topology/topology-data/models/topology-data-model';

@Component({
  selector: 'app-topology-viz',
  templateUrl: './topology-viz.component.html',
  styleUrls: ['./topology-viz.component.css'],
  encapsulation: ViewEncapsulation.None
})
export class TopologyVizComponent implements OnInit, OnDestroy, AfterViewInit {
  @ViewChild('topology') topologyEl: ElementRef;

  @Input() isLoading: boolean;
  @Input() hasLayers: boolean;
  @Input() svgTransform: SvgTransform;

  @Output() nodeClicked = new EventEmitter<NodeClickEvent>();
  @Output() nodeDblClicked = new EventEmitter<NodeClickEvent>();
  @Output() bviClicked = new EventEmitter<NodeClickEvent>();
  @Output() linkClicked = new EventEmitter<LinkClickEvent>();
  @Output() svgClicked = new EventEmitter<boolean>();
  @Output() transform = new EventEmitter<SvgTransform>();
  @Output() topologyRendered = new EventEmitter<boolean>();
  @Output() positionsChanged = new EventEmitter<TopologyDataModel>();

  private svg: d3.Selection<SVGSVGElement, {}, null, undefined>;
  private dropNode: NodeDataModel;
  private dropLink: EdgeDataModel;
  private subscriptions: Subscription[];
  private isDraggingItem = false;

  constructor(
    private coreService: CoreService,
    private topologyService: TopologyService,
    private topologyVizService: TopologyVizService
    ) {
  }

  ngOnInit() {
    this.subscriptions = [];

    this.subscriptions.push(
      this.topologyService.getTopologyDataObservable().subscribe(() => {
        this.renderTopology();
      })
    );
  }

  ngAfterViewInit() {
    this.svg = d3.select(this.topologyEl.nativeElement);
    const svgG = this.svg.select('.content');
    const zoomBeh = d3.zoom<SVGSVGElement, any>()
      .scaleExtent([0.25, 8])
      .on('zoom', this.zoomHandle(svgG));

    this.svg.call(zoomBeh);

    this.svg.on('dblclick.zoom', null);

    this.topologyVizService.setSvgObject(this.svg);
    this.topologyVizService.setZoomBeh(zoomBeh);
    this.renderTopology();

    if (this.svgTransform) {
      this.svg.select('#wrap')
        .attr('transform', 'translate(' + this.svgTransform.translate[0] + ', ' + this.svgTransform.translate[1] + ') ' +
        'scale(' + this.svgTransform.scale[0] + ')');
    }
  }

  /**
   * Aggregated function for setting parameters and events to all topology items
   */
  private renderTopology() {
    this.renderLinks(this.topologyService.getTopologyData().links, {selector: '.links'});
    this.renderNodes(this.topologyService.getTopologyData().nodes, {selector: '.nodes'});
    this.renderBVIs(this.topologyService.getTopologyData().bvis, {selector: '.bvis'});
    this.appendEventsToTopologyItems();
    this.topologyRendered.emit(true);
  }

  /**
   * Set parameters and events to link elements
   */
  private renderLinks(data: EdgeDataModel[], options: RenderOptions) {
    const links = this.svg.select(options.selector)
      .selectAll('.link')
      .data(data, function (l: EdgeDataModel) {
        return l.id;
      });

    links.exit().remove();

    links.enter().append('path')
      .classed('hidden', this.hasLayers)
      .attr('id', d => 'link' + d.id)
      .attr('stroke', d => d.color)
      .attr('stroke-width', d => d.width)
      .attr('d', (link: EdgeDataModel) => {
        let isBezier = false;

        const fromX = (link.fromNodeObj.x + link.fromNodeObj.iconWidth / 2);
        const fromY = (link.fromNodeObj.y + link.fromNodeObj.iconHeight / 2);
        const toX = (link.toNodeObj.x + link.toNodeObj.iconWidth / 2);
        const toY = (link.toNodeObj.y + link.toNodeObj.iconHeight / 2);

        const offsetYfrom = link.fromType === 'vxlan' ? -20 : 0;
        const offsetYto = link.toType === 'vxlan' ? -20 : 0;

        if (link.type === 'vxlan' && link.from.includes('vswitch') && link.to.includes('vswitch')) {
          // isBezier = true;
          isBezier = false;
        }

        if (isBezier) {
          const dx = toX - fromX;
          const dy = toY - fromY;
          const dr = Math.sqrt(dx * dx + dy * dy) * 3;

          return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' A ' + dr + ' ' + dr + ' 0 0 1' + toX + ' ' + (toY + offsetYto);
        } else {
          return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' L ' + toX + ' ' + (toY + offsetYto);
        }
      })
      .classed('dashed', d => d.isDashed)
      .classed('disabled', d => !d.clickable)
      .classed('link', true)
      .classed('vxlink', d => d.type === 'vxlan')
      .classed('bezier', d => d.type === 'vxlan' && d.from.includes('vswitch') && d.to.includes('vswitch'));
  }

  /**
   * Set parameters and events to node elements
   */
  private renderNodes(data: NodeDataModel[], options: RenderOptions) {
    const self = this;

    const nodesData = this.svg.select(options.selector)
      .selectAll('.node')
      .data(data, function (n: NodeDataModel) {
        return 'node' + n.id;
      });

    nodesData.exit().remove();

    nodesData.attr('id', d => 'node' + d.id)
      .attr('class', 'node hidden')
      .attr('transform', (d) => 'translate(' + d.x + ',' + d.y + ')')
      .attr('type', d => d.type);

    const nodesEnterG = nodesData.enter().append<SVGGElement>('g');

    nodesEnterG.attr('id', d => 'node' + d.id)
      .attr('class', 'node')
      .classed('hidden', this.hasLayers)
      .attr('transform', (d) => 'translate(' + d.x + ',' + d.y + ')')
      .attr('type', d => d.type);

    const iconNodes = nodesEnterG.filter((d) => {
      return d.icon !== '' ? true : false;
    });

    iconNodes.append('image')
      .attr('href', (d) => d.icon)
      .attr('width', d => d.iconWidth)
      .attr('height', d => d.iconHeight)
      .attr('class', 'node-icon');
    // TODO: append svg icons instead of images
    // nodes.append('svg-icon')
    // .attr('name', 'droppedItem.icon')

    iconNodes.append<SVGTextElement>('text')
      .attr('text-anchor', 'middle')
      .attr('dx', (d) => d.iconWidth / 2)
      .attr('dy', (d) => d.iconHeight + 20)
      .attr('fill', d => d.labelColor)
      .attr('class', 'node-text')
      .text((d) => d.label);

    const nonIconNodes = nodesEnterG.filter(d => {
      return d.icon === '' ? true : false;
    });

    nonIconNodes.each(function (n) {
      const node = d3.select(this);

      if (n instanceof K8sTopoNode) {
        node.append<SVGCircleElement>('circle')
        .attr('r', 50)
        .attr('stroke', d => n.stroke)
        .attr('stroke-width', d => n.strokeWidth);
      } else {
        node.append<SVGRectElement>('rect')
        .attr('width', d => {
          return self.getTextWidth(n.label) + 40;
        })
        .attr('height', 40)
        .attr('x', d => {
          return (self.getTextWidth(n.label) + 40) / -2;
        })
        .attr('y', -20)
        .attr('rx', 10)
        .attr('ry', 10)
        .attr('stroke', d => n.stroke)
        .attr('stroke-width', d => n.strokeWidth);
      }

      node.append<SVGTextElement>('text')
      .attr('text-anchor', 'middle')
      .attr('dy', 4)
      .attr('fill', d => n.labelColor)
      .attr('class', 'node-text')
      .text((d) => n.label);
    });

    // TODO: Optimalize update
    // this.svg.select('.nodes').selectAll('.node-icon').data(this.topologyService.getTopologyData().nodes)
    //   .attr('href', (d) => d.icon);

    // this.svg.select('.nodes').selectAll('.node-text').data(this.topologyService.getTopologyData().nodes)
    //   .attr('text-anchor', 'middle')
    //   .attr('dx', (d) => d.iconWidth / 2)
    //   .attr('dy', (d) => d.iconHeight + 20)
    //   .attr('fill', d => d.labelColor)
    //   .text((d) => d.label);
  }

  private renderBVIs(data: VppTopoBvi[], options: RenderOptions) {
    const bviData = this.svg.select(options.selector)
      .selectAll('.bvi')
      .data(data, function (d: VppTopoBvi) {
        return 'bvi' + d.id;
      });

    bviData.attr('id', d => 'bvi' + d.id)
      .attr('transform', (d) => 'translate(' + d.x + ',' + d.y + ')');

    const bviEnterG = bviData.enter().append<SVGGElement>('g')
      .attr('id', d => 'bvi' + d.id)
      .classed('bvi', true)
      .classed('hidden', this.hasLayers)
      .attr('transform', (d) => 'translate(' + d.x + ',' + d.y + ')');

    bviEnterG.append<SVGCircleElement>('circle')
      .attr('r', 15)
      .attr('cy', -20)
      .attr('fill', d => d.stroke);
  }

  /**
   * Append events to nodes and links
   */
  private appendEventsToTopologyItems() {
    const self = this;

    // fill links to array for further use
    const links = this.svg.select('.links')
      .selectAll('.link')
      .data(this.topologyService.getTopologyData().links)
      .on('mouseenter', d => this.dropLink = d)
      .on('mouseleave', d => this.dropLink = null)
      .on('click', function (d) {
        if (d.clickable) {
          self.linkClicked.emit({
            link: d,
            svgLink: this
          });
        }
      });

    // add events to topology nodes
    const nodes = this.svg.select('.nodes')
      .selectAll('.node')
      .data(this.topologyService.getTopologyData().nodes);

    nodes.filter(d => d.type === 'topology-item')
      .on('click', function (d) {
        self.nodeClicked.emit({
          node: d,
          svgNode: this
        });
      })
      .on('mouseenter', n => this.dropNode = n)
      .on('mouseleave', n => this.dropNode = null)
      .call(d3.drag<SVGGElement, NodeDataModel>()
        .on('drag', this.dragHandle(links))
        .on('end', this.stopHandle(links))
      );

    nodes.filter(d => d.nodeType === 'vswitch')
      .on('dblclick', function(d) {
        self.nodeDblClicked.emit({
          node: d,
          svgNode: this
        });
      });

    // add events to BVIs
    const bvis = this.svg.select('.bvis')
      .selectAll('.bvi')
      .data(this.topologyService.getTopologyData().bvis);

    bvis.filter(d => d.type === 'topology-item')
      .on('click', function (d) {
        self.bviClicked.emit({
          node: d,
          svgNode: this
        });
      })
      .on('mouseenter', n => this.dropNode = n)
      .on('mouseleave', n => this.dropNode = null);
  }

  private zoomHandle(svgSelection) {
    const self = this;

    return function (this: SVGSVGElement) {
      const zoomEvent: d3.D3ZoomEvent<SVGSVGElement, any> = d3.event;
      svgSelection.attr('transform', zoomEvent.transform.toString());
      self.transform.emit(self.coreService.parseTransform(zoomEvent.transform.toString()));
    };
  }

  private dragHandle(link: d3.Selection<any, EdgeDataModel, any, {}>) {
    const self = this;

    return function (this: SVGGElement, d: NodeDataModel) {
      const dragEvent: d3.D3DragEvent<SVGGElement, NodeDataModel, any> = d3.event;
      self.isDraggingItem = true;

      d.x = dragEvent.x;
      d.y = dragEvent.y;

      if (d instanceof VppTopoVswitch) {
        const bvi = self.topologyService.getTopologyData().getBVIById(d.id + '-bvi');

        if (bvi) {
          d3.select('#bvi' + d.id + '-bvi')
            .attr('transform', 'translate(' + d.x + ',' + d.y + ')');

          bvi.x = dragEvent.x;
          bvi.y = dragEvent.y;

          self.updateLinks(bvi, link);
        }
      }

      const dragNode = d3.select(this)
        .attr('transform', 'translate(' + d.x + ',' + d.y + ')');

      if (!(dragEvent.dx === 0 || dragEvent.dy === 0)) {
        dragNode.classed('node-dragging', true);
      }

      self.updateLinks(d, link);
    };
  }

  private stopHandle(links: d3.Selection<any, EdgeDataModel, any, {}>) {
    const self = this;

    return function (this: SVGGElement, d: NodeDataModel) {
      if (!self.isDraggingItem) {
        return;
      }

      self.isDraggingItem = false;

      d3.select(this).classed('node-dragging', false);
      d3.selectAll('.link-dragging').classed('link-dragging', false);

      self.positionsChanged.emit(self.topologyService.getTopologyData());
    };
  }

  private updateLinks(d: NodeDataModel, links: d3.Selection<any, EdgeDataModel, any, {}>) {
    const connectedLinks = links.filter(
      (link) => {
        return (d.id === link.from || d.id === link.to);
      }
    );

    connectedLinks
      .attr('d', (link: EdgeDataModel) => {
        let isBezier = false;

        const fromX = (link.fromNodeObj.x + link.fromNodeObj.iconWidth / 2);
        const fromY = (link.fromNodeObj.y + link.fromNodeObj.iconHeight / 2);
        const toX = (link.toNodeObj.x + link.toNodeObj.iconWidth / 2);
        const toY = (link.toNodeObj.y + link.toNodeObj.iconHeight / 2);

        const offsetYfrom = link.fromType === 'vxlan' ? -20 : 0;
        const offsetYto = link.toType === 'vxlan' ? -20 : 0;

        if (link.type === 'vxlan' && link.from.includes('vswitch') && link.to.includes('vswitch')) {
          // isBezier = true;
          isBezier = false;
        }

        if (isBezier) {
          const dx = toX - fromX;
          const dy = toY - fromY;
          const dr = Math.sqrt(dx * dx + dy * dy) * 3;

          return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' A ' + dr + ' ' + dr + ' 0 0 1' + toX + ' ' + (toY + offsetYto);
        } else {
          return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' L ' + toX + ' ' + (toY + offsetYto);
        }
      })
      .classed('link-dragging', true);
  }

  public checkSvgClick(e: Event) {
    // e.stopPropagation();
    if (!this.isTopologyItemClicked()) {
      this.svgClicked.emit(true);
    }
  }

  private isTopologyItemClicked(): boolean {
    if (this.dropNode || this.dropLink) {
      return true;
    } else {
      return false;
    }
  }

  private getTextWidth(text: string): number {
    const label = this.svg.append<SVGTextElement>('text').attr('class', 'invisible').text(text);
    const labelWidth = label.node().getBBox().width;
    label.remove();

    return labelWidth;
  }

  ngOnDestroy(): void {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
