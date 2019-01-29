import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ModalService } from '../../services/modal.service';

@Component({
  selector: 'app-code-modal',
  templateUrl: './code-modal.component.html',
  styleUrls: ['./code-modal.component.css']
})
export class CodeModalComponent implements OnInit, OnDestroy {

  public isModalOpened: boolean;
  public api: string;
  public response: string;

  private subscriptions: Subscription[];

  constructor(
    private modalService: ModalService
  ) { }

  ngOnInit() {
    this.subscriptions = [];
    this.isModalOpened = false;

    this.subscriptions.push(
      this.modalService.outputSubject.subscribe(obj => {
        this.api = obj.api;
        this.response = JSON.stringify(JSON.parse(obj.response), null, 2);
        this.isModalOpened = true;
      })
    );
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
