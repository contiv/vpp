import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { CodeModalComponent } from './code-modal.component';

describe('CodeModalComponent', () => {
  let component: CodeModalComponent;
  let fixture: ComponentFixture<CodeModalComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ CodeModalComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(CodeModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
