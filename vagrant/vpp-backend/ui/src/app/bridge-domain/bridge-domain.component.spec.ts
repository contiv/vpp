import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { BridgeDomainComponent } from './bridge-domain.component';

describe('BridgeDomainComponent', () => {
  let component: BridgeDomainComponent;
  let fixture: ComponentFixture<BridgeDomainComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ BridgeDomainComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(BridgeDomainComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
