import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VswitchDiagramControlComponent } from './vswitch-diagram-control.component';

describe('VswitchDiagramControlComponent', () => {
  let component: VswitchDiagramControlComponent;
  let fixture: ComponentFixture<VswitchDiagramControlComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VswitchDiagramControlComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VswitchDiagramControlComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
