import { Component, OnInit } from '@angular/core';
import { DataService } from './shared/services/data.service';
import { AppConfig } from './app-config';
import { ModalService } from './shared/services/modal.service';
import { SettingsService } from './shared/services/settings.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  public isDataLoading: boolean;
  public isWebTerminalOpened: boolean;
  private preventRefresh: boolean;
  private reloadTimer: any;

  constructor(
    private dataService: DataService,
    private modalService: ModalService,
    private settingsService: SettingsService
  ) { }

  ngOnInit() {
    this.isWebTerminalOpened = false;
    this.preventRefresh = true;

    if (AppConfig.ENABLE_DATA_REFRESH) {
      this.reloadTimer = setInterval(() => this.reloadData(), AppConfig.POLLING_FREQ * 1000);
    }

    this.settingsService.settingsSubject.subscribe(settings => {
      clearInterval(this.reloadTimer);

      if (settings.pollingEnabled) {
        this.reloadTimer = setInterval(() => this.reloadData(), settings.pollingFrequency * 1000);
      }
    });

    this.dataService.preventRefreshSubject.subscribe(isPrevented => this.preventRefresh = isPrevented);
    this.dataService.isDataLoading.subscribe(state => this.isDataLoading = state);
  }

  public reloadData(force?: boolean) {
    if (force) {
      this.dataService.loadData();
      return;
    }

    if (!this.isDataLoading && !this.preventRefresh) {
      this.dataService.loadData();
    }
  }

  public openSettings() {
    this.modalService.showSettings();
  }

}
