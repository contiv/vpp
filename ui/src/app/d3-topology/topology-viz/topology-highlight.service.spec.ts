import { TestBed } from '@angular/core/testing';

import { TopologyHighlightService } from './topology-highlight.service';

describe('TopologyHighlightService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: TopologyHighlightService = TestBed.get(TopologyHighlightService);
    expect(service).toBeTruthy();
  });
});
