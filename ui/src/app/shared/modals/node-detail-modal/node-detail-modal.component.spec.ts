import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { NodeDetailModalComponent } from './node-detail-modal.component';

describe('NodeDetailModalComponent', () => {
  let component: NodeDetailModalComponent;
  let fixture: ComponentFixture<NodeDetailModalComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ NodeDetailModalComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(NodeDetailModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
