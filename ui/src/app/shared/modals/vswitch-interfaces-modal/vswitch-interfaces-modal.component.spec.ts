import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VswitchInterfacesModalComponent } from './vswitch-interfaces-modal.component';

describe('VswitchInterfacesModalComponent', () => {
  let component: VswitchInterfacesModalComponent;
  let fixture: ComponentFixture<VswitchInterfacesModalComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VswitchInterfacesModalComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VswitchInterfacesModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
