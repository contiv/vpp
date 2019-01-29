import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ModalService } from '../../services/modal.service';
import { K8sPodModel } from '../../models/k8s/k8s-pod-model';

@Component({
  selector: 'app-containers-modal',
  templateUrl: './containers-modal.component.html',
  styleUrls: ['./containers-modal.component.css']
})
export class ContainersModalComponent implements OnInit, OnDestroy {

  public isModalOpened: boolean;
  public pod: K8sPodModel;

  private subscriptions: Subscription[];

  constructor(
    private modalService: ModalService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.isModalOpened = false;

    this.subscriptions.push(
      this.modalService.podDataSubject.subscribe(pod => {
        this.isModalOpened = true;
        this.pod = pod;
      })
    );
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
