import { TestBed } from '@angular/core/testing';

import { VswitchDiagramService } from './vswitch-diagram.service';

describe('VswitchDiagramService', () => {
  beforeEach(() => TestBed.configureTestingModule({}));

  it('should be created', () => {
    const service: VswitchDiagramService = TestBed.get(VswitchDiagramService);
    expect(service).toBeTruthy();
  });
});
