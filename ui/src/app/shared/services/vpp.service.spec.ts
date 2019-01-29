import { TestBed } from '@angular/core/testing';

import { VppService } from './vpp.service';

describe('VppService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: VppService = TestBed.get(VppService);
    expect(service).toBeTruthy();
  });
});
