import { TestBed } from '@angular/core/testing';

import { SidepanelService } from './sidepanel.service';

describe('SidepanelService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: SidepanelService = TestBed.get(SidepanelService);
    expect(service).toBeTruthy();
  });
});
