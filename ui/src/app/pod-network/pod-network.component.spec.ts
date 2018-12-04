import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { PodNetworkComponent } from './pod-network.component';

describe('PodNetworkComponent', () => {
  let component: PodNetworkComponent;
  let fixture: ComponentFixture<PodNetworkComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ PodNetworkComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(PodNetworkComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
