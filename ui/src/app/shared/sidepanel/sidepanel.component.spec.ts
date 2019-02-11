import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { SidepanelComponent } from './sidepanel.component';

describe('SidepanelComponent', () => {
  let component: SidepanelComponent;
  let fixture: ComponentFixture<SidepanelComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ SidepanelComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(SidepanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
