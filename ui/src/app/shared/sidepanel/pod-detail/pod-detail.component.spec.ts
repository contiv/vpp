import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { PodDetailComponent } from './pod-detail.component';

describe('PodDetailComponent', () => {
  let component: PodDetailComponent;
  let fixture: ComponentFixture<PodDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ PodDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(PodDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
