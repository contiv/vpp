import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VswitchDiagramModalComponent } from './vswitch-diagram-modal.component';

describe('VswitchDiagramModalComponent', () => {
  let component: VswitchDiagramModalComponent;
  let fixture: ComponentFixture<VswitchDiagramModalComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VswitchDiagramModalComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VswitchDiagramModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
