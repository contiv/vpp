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
import { DataService } from '../../shared/services/data.service';

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
  private topoSubscription: Subscription;
  private isDraggingItem = false;
  private simulation: d3.Simulation<NodeDataModel, EdgeDataModel>;

  constructor(
    private coreService: CoreService,
    private topologyService: TopologyService,
    private topologyVizService: TopologyVizService,
    private dataService: DataService
    ) {
  }

  ngOnInit() {
    this.topoSubscription = this.topologyService.getTopologyDataObservable().subscribe(() => {
      this.renderTopology();
    });
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

  private forceTopologyLayout() {
    const svgRect = this.svg.node().getBoundingClientRect();

    const links = this.svg.select('.links')
      .selectAll('.link')
      .data(this.topologyService.getTopologyData().links);

    const nodes = this.svg.select('.nodes')
      .selectAll('.node')
      .data(this.topologyService.getTopologyData().nodes);

    this.simulation = d3.forceSimulation<NodeDataModel, EdgeDataModel>(this.topologyService.getTopologyData().nodes)
      .force('charge', d3.forceManyBody().strength(-500))
      .force('link', d3.forceLink<NodeDataModel, EdgeDataModel>(this.topologyService.getTopologyData().links)
        .id(d => d.id)
        .distance(d => {
          if (d.fromNodeObj.nodeType === 'node' && d.toNodeObj.nodeType === 'node') {
            return 400;
          } else if (d.fromNodeObj instanceof VppTopoVswitch && d.toNodeObj instanceof VppTopoBvi) {
            return 20;
          } else if (d.fromNodeObj instanceof VppTopoVswitch) {
            return 300;
          } else if (d.type === 'vxlan') {
            return 400;
          } else {
            return 200;
          }
        })
      )
      .force('center', d3.forceCenter(svgRect.width / 2, svgRect.height / 2))
      .on('tick', this.ticked(links, nodes))
      .on('end', this.forceEnded())
      .alphaDecay(0.03);
  }

  private forceEnded() {
    const self = this;

    return function() {
      self.positionsChanged.emit(self.topologyService.getTopologyData());
    };
  }

  private ticked(links: d3.Selection<any, EdgeDataModel, any, {}>, nodes: d3.Selection<any, NodeDataModel, any, {}>) {
    const self = this;

    return function() {
      links.attr('d', (link: EdgeDataModel) => {
        const fromX = (link.fromNodeObj.x + link.fromNodeObj.iconWidth / 2);
        const fromY = (link.fromNodeObj.y + link.fromNodeObj.iconHeight / 2);
        const toX = (link.toNodeObj.x + link.toNodeObj.iconWidth / 2);
        const toY = (link.toNodeObj.y + link.toNodeObj.iconHeight / 2);

        const offsetYfrom = link.fromType === 'vxlan' ? -20 : 0;
        const offsetYto = link.toType === 'vxlan' ? -20 : 0;

        return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' L ' + toX + ' ' + (toY + offsetYto);
      });

      nodes.attr('transform', (d) => 'translate(' + d.x + ',' + d.y + ')');
    };
  }

  /**
   * Aggregated function for setting parameters and events to all topology items
   */
  private renderTopology() {
    this.renderLinks(this.topologyService.getTopologyData().links, {selector: '.links'});
    this.renderNodes(this.topologyService.getTopologyData().nodes, {selector: '.nodes'});
    this.appendEventsToTopologyItems();
    this.forceTopologyLayout();

    if (this.topologyService.getTopologyData().nodes.length) {
      this.topologyRendered.emit(true);
    }
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
        const fromX = (link.fromNodeObj.x + link.fromNodeObj.iconWidth / 2);
        const fromY = (link.fromNodeObj.y + link.fromNodeObj.iconHeight / 2);
        const toX = (link.toNodeObj.x + link.toNodeObj.iconWidth / 2);
        const toY = (link.toNodeObj.y + link.toNodeObj.iconHeight / 2);

        const offsetYfrom = link.fromType === 'vxlan' ? -20 : 0;
        const offsetYto = link.toType === 'vxlan' ? -20 : 0;

        return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' L ' + toX + ' ' + (toY + offsetYto);
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

    nodesData.classed('node', true)
      .attr('transform', (d) => 'translate(' + d.x + ',' + d.y + ')')
      .attr('type', d => d.type);

    const nodesEnterG = nodesData.enter().append<SVGGElement>('g');

    nodesEnterG.attr('id', d => 'node' + d.id)
      .classed('node', true)
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
      return d.icon === '' && !(d instanceof VppTopoBvi) ? true : false;
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

    const bviNodes = nodesEnterG.filter(d => d instanceof VppTopoBvi);
    bviNodes.attr('id', d => 'bvi' + d.id)
      .classed('bvi', true);

    bviNodes.each(function(b) {
      const bvi = d3.select(this);

      bvi.append<SVGCircleElement>('circle')
        .attr('r', 15)
        .attr('cy', -20)
        .attr('fill', b.stroke);
    });
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
        if (d instanceof VppTopoBvi) {
          self.bviClicked.emit({
            node: d,
            svgNode: this
          });
        } else {
          self.nodeClicked.emit({
            node: d,
            svgNode: this
          });
        }
      })
      .on('dblclick', function(d) {
        if (d instanceof VppTopoVswitch) {
          self.nodeDblClicked.emit({
            node: d,
            svgNode: this
          });
        }
      })
      .on('mouseenter', n => this.dropNode = n)
      .on('mouseleave', n => this.dropNode = null)
      .call(d3.drag<SVGGElement, NodeDataModel>()
        .on('start', this.startHandle(links))
        .on('drag', this.dragHandle(links))
        .on('end', this.stopHandle(links))
      );
  }

  private zoomHandle(svgSelection) {
    const self = this;

    return function (this: SVGSVGElement) {
      const zoomEvent: d3.D3ZoomEvent<SVGSVGElement, any> = d3.event;
      svgSelection.attr('transform', zoomEvent.transform.toString());
      self.transform.emit(self.coreService.parseTransform(zoomEvent.transform.toString()));
    };
  }

  private startHandle(links: d3.Selection<any, EdgeDataModel, any, {}>) {
    const self = this;

    return function (this: SVGGElement, d: NodeDataModel) {
      self.dataService.preventRefresh();

      const dragEvent: d3.D3DragEvent<SVGGElement, NodeDataModel, any> = d3.event;
      if (!d3.event.active) {
        self.simulation.alphaTarget(0.1).restart();
      }

      dragEvent.subject.fx = dragEvent.subject.x;
      dragEvent.subject.fy = dragEvent.subject.y;

      self.topologyService.getTopologyData().nodes.forEach(n => {
        n.fx = null;
        n.fy = null;
      });
    };
  }

  private dragHandle(link: d3.Selection<any, EdgeDataModel, any, {}>) {
    const self = this;

    return function (this: SVGGElement, d: NodeDataModel) {
      const dragEvent: d3.D3DragEvent<SVGGElement, NodeDataModel, any> = d3.event;
      self.isDraggingItem = true;

      d.x = dragEvent.x;
      d.y = dragEvent.y;

      dragEvent.subject.fx = dragEvent.x;
      dragEvent.subject.fy = dragEvent.y;

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
      self.dataService.allowRefresh();

      const dragEvent: d3.D3DragEvent<SVGGElement, NodeDataModel, any> = d3.event;
      if (!d3.event.active) {
        self.simulation.alphaTarget(0);
      }

      dragEvent.subject.fx = null;
      dragEvent.subject.fy = null;

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
        const fromX = (link.fromNodeObj.x + link.fromNodeObj.iconWidth / 2);
        const fromY = (link.fromNodeObj.y + link.fromNodeObj.iconHeight / 2);
        const toX = (link.toNodeObj.x + link.toNodeObj.iconWidth / 2);
        const toY = (link.toNodeObj.y + link.toNodeObj.iconHeight / 2);

        const offsetYfrom = link.fromType === 'vxlan' ? -20 : 0;
        const offsetYto = link.toType === 'vxlan' ? -20 : 0;

        return 'M ' + fromX + ' ' + (fromY + offsetYfrom) + ' L ' + toX + ' ' + (toY + offsetYto);
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
    if (this.topoSubscription) {
      this.topoSubscription.unsubscribe();
    }
  }

}
