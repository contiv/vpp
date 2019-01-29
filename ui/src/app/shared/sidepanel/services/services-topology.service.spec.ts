import { TestBed } from '@angular/core/testing';

import { ServicesTopologyService } from './services-topology.service';

describe('ServicesTopologyService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: ServicesTopologyService = TestBed.get(ServicesTopologyService);
    expect(service).toBeTruthy();
  });
});
