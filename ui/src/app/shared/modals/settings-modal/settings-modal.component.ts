import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ModalService } from '../../services/modal.service';
import { SettingsService } from '../../services/settings.service';
import { SettingsObject } from '../../interfaces/settings-object';

@Component({
  selector: 'app-settings-modal',
  templateUrl: './settings-modal.component.html',
  styleUrls: ['./settings-modal.component.css']
})
export class SettingsModalComponent implements OnInit, OnDestroy {

  public isModalOpened: boolean;
  public settings: SettingsObject;

  private subscriptions: Subscription[];

  constructor(
    private modalService: ModalService,
    private settingsService: SettingsService
  ) { }

  ngOnInit() {
    this.init();
    this.subscriptions = [];
    this.isModalOpened = false;

    this.subscriptions.push(
      this.modalService.settingsSubject.subscribe(state => {
        this.isModalOpened = state;
        this.init();
      })
    );
  }

  public save() {
    this.settingsService.saveSettings(this.settings);
    this.isModalOpened = false;
  }

  public close() {
    this.isModalOpened = false;
  }

  private init() {
    this.settings = Object.assign({}, this.settingsService.settings);
  }

  ngOnDestroy() {
    this.subscriptions.forEach(s => s.unsubscribe());
  }

}
