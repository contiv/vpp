import { TestBed } from '@angular/core/testing';

import { K8sTopologyService } from './k8s-topology.service';

describe('K8sTopologyService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: K8sTopologyService = TestBed.get(K8sTopologyService);
    expect(service).toBeTruthy();
  });
});
