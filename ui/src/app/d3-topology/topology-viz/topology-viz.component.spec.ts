import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { TopologyVizComponent } from './topology-viz.component';

describe('TopologyVizComponent', () => {
  let component: TopologyVizComponent;
  let fixture: ComponentFixture<TopologyVizComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ TopologyVizComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(TopologyVizComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
