import { TestBed } from '@angular/core/testing';

import { TopologyVizService } from './topology-viz.service';

describe('TopologyVizService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: TopologyVizService = TestBed.get(TopologyVizService);
    expect(service).toBeTruthy();
  });
});
