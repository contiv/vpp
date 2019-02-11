import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { BridgeDomainControlComponent } from './bridge-domain-control.component';

describe('BridgeDomainControlComponent', () => {
  let component: BridgeDomainControlComponent;
  let fixture: ComponentFixture<BridgeDomainControlComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ BridgeDomainControlComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(BridgeDomainControlComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
