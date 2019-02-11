import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VswitchDiagramComponent } from './vswitch-diagram.component';

describe('VswitchDiagramComponent', () => {
  let component: VswitchDiagramComponent;
  let fixture: ComponentFixture<VswitchDiagramComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VswitchDiagramComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VswitchDiagramComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
