import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { KubernetesComponent } from './kubernetes/kubernetes.component';
import { PodNetworkComponent } from './pod-network/pod-network.component';
import { NodesComponent } from './shared/sidepanel/nodes/nodes.component';
import { PodsComponent } from './shared/sidepanel/pods/pods.component';
import { NodeDetailComponent } from './shared/sidepanel/node-detail/node-detail.component';
import { ServicesComponent } from './shared/sidepanel/services/services.component';
import { PodDetailComponent } from './shared/sidepanel/pod-detail/pod-detail.component';
import { BviDetailComponent } from './shared/sidepanel/bvi-detail/bvi-detail.component';
import { VppLinkDetailComponent } from './shared/sidepanel/vpp-link-detail/vpp-link-detail.component';
import { VxtunnelDetailComponent } from './shared/sidepanel/vxtunnel-detail/vxtunnel-detail.component';
import { VppPodDetailComponent } from './shared/sidepanel/vpp-pod-detail/vpp-pod-detail.component';
import { VswitchDetailComponent } from './shared/sidepanel/vswitch-detail/vswitch-detail.component';
import { BridgeDomainComponent } from './bridge-domain/bridge-domain.component';
import { VswitchDiagramComponent } from './vswitch-diagram/vswitch-diagram.component';
import { VswitchDiagramControlComponent } from './shared/sidepanel/vswitch-diagram-control/vswitch-diagram-control.component';

const routes: Routes = [
  { path: '', redirectTo: 'kubernetes', pathMatch: 'full' },
  { path: 'kubernetes', component: KubernetesComponent, children: [
    { path: '', redirectTo: 'nodes', pathMatch: 'full' },
    { path: 'nodes', component: NodesComponent },
    { path: 'node/:id', component: NodeDetailComponent},
    { path: 'pods', component: PodsComponent },
    { path: 'pod/:id', component: PodDetailComponent},
    { path: 'vppPod/:id', component: VppPodDetailComponent},
    { path: 'vswitch/:id', component: VswitchDetailComponent},
    { path: 'vppLink/:id', component: VppLinkDetailComponent}
  ] },
  { path: 'contiv', component: PodNetworkComponent, children: [
    { path: '', component: PodsComponent },
    { path: 'node/:id', component: NodeDetailComponent},
    { path: 'pod/:id', component: PodDetailComponent},
    { path: 'vppPod/:id', component: VppPodDetailComponent},
    { path: 'vswitch/:id', component: VswitchDetailComponent},
    { path: 'bvi/:id', component: BviDetailComponent},
    { path: 'vppLink/:from/:to', component: VppLinkDetailComponent},
    { path: 'vxtunnel/:from/:to', component: VxtunnelDetailComponent}
  ] },
  { path: 'bridge-domain', component: BridgeDomainComponent, children: [
    { path: 'node/:id', component: NodeDetailComponent},
    { path: 'pod/:id', component: PodDetailComponent},
    { path: 'vppPod/:id', component: VppPodDetailComponent},
    { path: 'vswitch/:id', component: VswitchDetailComponent},
    { path: 'bvi/:id', component: BviDetailComponent},
    { path: 'vppLink/:from/:to', component: VppLinkDetailComponent},
    { path: 'vxtunnel/:from/:to', component: VxtunnelDetailComponent}
  ] },
  { path: 'bridge-domain/:id', component: BridgeDomainComponent},
  { path: 'vswitch-diagram/:id', component: VswitchDiagramComponent, children: [
    { path: '', component: VswitchDiagramControlComponent}
  ] },
  { path: 'services', component: ServicesComponent }
];

@NgModule({
  imports: [ RouterModule.forRoot(routes) ],
  exports: [ RouterModule ]
})
export class AppRoutingModule {}
