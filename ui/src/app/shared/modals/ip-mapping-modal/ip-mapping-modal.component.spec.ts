import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { IpMappingModalComponent } from './ip-mapping-modal.component';

describe('IpMappingModalComponent', () => {
  let component: IpMappingModalComponent;
  let fixture: ComponentFixture<IpMappingModalComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ IpMappingModalComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(IpMappingModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
