import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VppPodDetailComponent } from './vpp-pod-detail.component';

describe('VppPodDetailComponent', () => {
  let component: VppPodDetailComponent;
  let fixture: ComponentFixture<VppPodDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VppPodDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VppPodDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
