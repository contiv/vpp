import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { HttpClientModule } from '@angular/common/http';

import { ClarityModule, ClrFormsNextModule } from '@clr/angular';
import { D3TopologyModule } from './d3-topology/d3-topology.module';
import { AppRoutingModule } from './app-routing.module';

import { KubernetesService } from './shared/services/kubernetes.service';
import { SidepanelService } from './shared/sidepanel/sidepanel.service';
import { VppService } from './shared/services/vpp.service';
import { DataService } from './shared/services/data.service';
import { PodTopologyService } from './pod-network/pod-topology.service';
import { K8sTopologyService } from './kubernetes/k8s-topology.service';
import { LayoutService } from './shared/services/layout.service';
import { ModalService } from './shared/services/modal.service';
import { VswitchDiagramService } from './vswitch-diagram/vswitch-diagram.service';

import { AppComponent } from './app.component';
import { KubernetesComponent } from './kubernetes/kubernetes.component';
import { PodNetworkComponent } from './pod-network/pod-network.component';
import { ManagerComponent } from './manager/manager.component';
import { VppComponent } from './vpp/vpp.component';
import { TerminalComponent } from './terminal/terminal.component';
import { SidepanelComponent } from './shared/sidepanel/sidepanel.component';
import { PodsComponent } from './shared/sidepanel/pods/pods.component';
import { NodesComponent } from './shared/sidepanel/nodes/nodes.component';
import { NodeDetailComponent } from './shared/sidepanel/node-detail/node-detail.component';
import { ServicesComponent } from './shared/sidepanel/services/services.component';
import { PoliciesComponent } from './shared/sidepanel/policies/policies.component';
import { PodDetailComponent } from './shared/sidepanel/pod-detail/pod-detail.component';
import { FormComponent } from './shared/form/form.component';
import { BviDetailComponent } from './shared/sidepanel/bvi-detail/bvi-detail.component';
import { IpMappingModalComponent } from './shared/modals/ip-mapping-modal/ip-mapping-modal.component';
import { VppLinkDetailComponent } from './shared/sidepanel/vpp-link-detail/vpp-link-detail.component';
import { VxtunnelDetailComponent } from './shared/sidepanel/vxtunnel-detail/vxtunnel-detail.component';
import { VppPodDetailComponent } from './shared/sidepanel/vpp-pod-detail/vpp-pod-detail.component';
import { VswitchDetailComponent } from './shared/sidepanel/vswitch-detail/vswitch-detail.component';
import { VswitchInterfacesModalComponent } from './shared/modals/vswitch-interfaces-modal/vswitch-interfaces-modal.component';
import { BridgeDomainComponent } from './bridge-domain/bridge-domain.component';
import { VswitchDiagramComponent } from './vswitch-diagram/vswitch-diagram.component';
import { VppInterfaceDetailComponent } from './shared/sidepanel/vpp-interface-detail/vpp-interface-detail.component';
import { VswitchDiagramControlComponent } from './shared/sidepanel/vswitch-diagram-control/vswitch-diagram-control.component';
import { NodeDetailModalComponent } from './shared/modals/node-detail-modal/node-detail-modal.component';
import { BridgeDomainControlComponent } from './shared/sidepanel/bridge-domain-control/bridge-domain-control.component';
import { CodeModalComponent } from './shared/modals/code-modal/code-modal.component';
import { BridgeDomainService } from './bridge-domain/bridge-domain.service';

@NgModule({
  declarations: [
    AppComponent,
    KubernetesComponent,
    PodNetworkComponent,
    ManagerComponent,
    VppComponent,
    TerminalComponent,
    PodsComponent,
    NodesComponent,
    SidepanelComponent,
    NodeDetailComponent,
    ServicesComponent,
    PoliciesComponent,
    PodDetailComponent,
    FormComponent,
    BviDetailComponent,
    IpMappingModalComponent,
    VppLinkDetailComponent,
    VxtunnelDetailComponent,
    VppPodDetailComponent,
    VswitchDetailComponent,
    VswitchInterfacesModalComponent,
    BridgeDomainComponent,
    VswitchDiagramComponent,
    VppInterfaceDetailComponent,
    VswitchDiagramControlComponent,
    NodeDetailModalComponent,
    BridgeDomainControlComponent,
    CodeModalComponent
  ],
  imports: [
    BrowserModule,
    HttpClientModule,
    ClarityModule,
    ClrFormsNextModule,
    BrowserAnimationsModule,
    FormsModule,
    D3TopologyModule,
    AppRoutingModule
  ],
  providers: [
    KubernetesService,
    SidepanelService,
    VppService,
    DataService,
    PodTopologyService,
    K8sTopologyService,
    LayoutService,
    ModalService,
    VswitchDiagramService,
    BridgeDomainService
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
