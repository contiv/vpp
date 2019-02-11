import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { VxtunnelDetailComponent } from './vxtunnel-detail.component';

describe('VxtunnelDetailComponent', () => {
  let component: VxtunnelDetailComponent;
  let fixture: ComponentFixture<VxtunnelDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ VxtunnelDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(VxtunnelDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
