import { TestBed } from '@angular/core/testing';

import { TopologyService } from './topology.service';

describe('TopologyService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: TopologyService = TestBed.get(TopologyService);
    expect(service).toBeTruthy();
  });
});
