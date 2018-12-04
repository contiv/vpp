import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { KubernetesService } from '../../services/kubernetes.service';
import { K8sPolicyModel } from '../../models/k8s/k8s-policy-model';
import { AppConfig } from 'src/app/app-config';

@Component({
  selector: 'app-policies',
  templateUrl: './policies.component.html',
  styleUrls: ['./policies.component.css']
})
export class PoliciesComponent implements OnInit, OnDestroy {

  public policies: K8sPolicyModel[];
  private policiesSubscription: Subscription;

  constructor(
    private k8sService: KubernetesService
  ) { }

  ngOnInit() {
    this.policies = [];
    this.policiesSubscription = this.k8sService.loadPolicies(AppConfig.K8S_REST_MASTER_URL).subscribe(res => this.policies = res);
  }

  ngOnDestroy() {
    if (this.policiesSubscription) {
      this.policiesSubscription.unsubscribe();
    }
  }

}
