import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VppInterfaceDetailComponent } from './vpp-interface-detail.component';

describe('VppInterfaceDetailComponent', () => {
  let component: VppInterfaceDetailComponent;
  let fixture: ComponentFixture<VppInterfaceDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VppInterfaceDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VppInterfaceDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
