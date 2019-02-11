import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VswitchDetailComponent } from './vswitch-detail.component';

describe('VswitchDetailComponent', () => {
  let component: VswitchDetailComponent;
  let fixture: ComponentFixture<VswitchDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VswitchDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VswitchDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
