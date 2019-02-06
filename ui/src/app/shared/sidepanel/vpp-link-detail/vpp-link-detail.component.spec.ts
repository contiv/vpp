import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VppLinkDetailComponent } from './vpp-link-detail.component';

describe('VppLinkDetailComponent', () => {
  let component: VppLinkDetailComponent;
  let fixture: ComponentFixture<VppLinkDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VppLinkDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VppLinkDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
