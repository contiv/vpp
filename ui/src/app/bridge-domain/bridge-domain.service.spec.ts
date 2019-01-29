import { TestBed } from '@angular/core/testing';

import { BridgeDomainService } from './bridge-domain.service';

describe('BridgeDomainService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: BridgeDomainService = TestBed.get(BridgeDomainService);
    expect(service).toBeTruthy();
  });
});
