import { Injectable } from '@angular/core';
import { AppConfig } from '../../app-config';
import { SettingsObject } from '../interfaces/settings-object';
import { Subject } from 'rxjs';

@Injectable({
  providedIn: 'root'
})
export class SettingsService {

  public settings: SettingsObject;
  public settingsSubject: Subject<SettingsObject> = new Subject<SettingsObject>();

  constructor() {
    this.settings = <SettingsObject>{
      pollingEnabled: AppConfig.ENABLE_DATA_REFRESH,
      pollingFrequency: AppConfig.POLLING_FREQ
    };
  }

  public saveSettings(data: SettingsObject) {
    this.settings = data;
    this.settingsSubject.next(data);
  }

}
