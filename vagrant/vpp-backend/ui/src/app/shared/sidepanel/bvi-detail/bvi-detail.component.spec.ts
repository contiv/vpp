import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { BviDetailComponent } from './bvi-detail.component';

describe('BviDetailComponent', () => {
  let component: BviDetailComponent;
  let fixture: ComponentFixture<BviDetailComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ BviDetailComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(BviDetailComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
