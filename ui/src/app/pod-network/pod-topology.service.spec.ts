import { TestBed } from '@angular/core/testing';

import { PodTopologyService } from './pod-topology.service';

describe('PodTopologyService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: PodTopologyService = TestBed.get(PodTopologyService);
    expect(service).toBeTruthy();
  });
});
