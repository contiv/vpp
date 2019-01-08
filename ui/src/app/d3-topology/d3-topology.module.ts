import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';

import { CoreService } from './shared/core.service';
import { TopologyService } from './topology/topology.service';
import { TopologyVizService } from './topology-viz/topology-viz.service';
import { TopologyHighlightService } from './topology-viz/topology-highlight.service';

import { TopologyVizComponent } from './topology-viz/topology-viz.component';

@NgModule({
  imports: [
    CommonModule
  ],
  providers: [
    CoreService,
    TopologyService,
    TopologyVizService,
    TopologyHighlightService
  ],
  declarations: [
    TopologyVizComponent
  ],
  exports: [
    TopologyVizComponent
  ]
})
export class D3TopologyModule { }
