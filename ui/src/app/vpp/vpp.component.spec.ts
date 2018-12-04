import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VppComponent } from './vpp.component';

describe('VppComponent', () => {
  let component: VppComponent;
  let fixture: ComponentFixture<VppComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VppComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VppComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
