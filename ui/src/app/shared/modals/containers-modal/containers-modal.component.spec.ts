import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { ContainersModalComponent } from './containers-modal.component';

describe('ContainersModalComponent', () => {
  let component: ContainersModalComponent;
  let fixture: ComponentFixture<ContainersModalComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ ContainersModalComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(ContainersModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
