import { Component, OnInit } from '@angular/core';
import { DataService } from './shared/services/data.service';
import { AppConfig } from './app-config';

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
    private dataService: DataService
  ) { }

  ngOnInit() {
    this.isWebTerminalOpened = false;
    this.preventRefresh = false;

    this.reloadTimer = setInterval(() => this.reloadData(), AppConfig.POLLING_FREQ);
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
}
