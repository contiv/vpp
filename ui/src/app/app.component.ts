import { Component, OnInit } from '@angular/core';
import { DataService } from './shared/services/data.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  public isDataLoading: boolean;

  constructor(
    private dataService: DataService
  ) { }

  ngOnInit() {
    this.dataService.isDataLoading.subscribe(state => this.isDataLoading = state);
  }

  public reloadData() {
    if (!this.isDataLoading) {
      this.dataService.loadData();
    }
  }
}
