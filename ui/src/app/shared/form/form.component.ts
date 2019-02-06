import { Component, OnInit, Input, ViewEncapsulation, Output, EventEmitter } from '@angular/core';
import { FormObject } from '../interfaces/form-object';

@Component({
  selector: 'app-form',
  templateUrl: './form.component.html',
  styleUrls: ['./form.component.css'],
  encapsulation: ViewEncapsulation.None
})
export class FormComponent implements OnInit {

  @Input() data: FormObject[];
  @Input() title: string;
  @Input() buttons: string[];

  @Output() btnclick: EventEmitter<number> = new EventEmitter<number>();

  constructor() { }

  ngOnInit() {
  }

  public buttonClick(i: number) {
    this.btnclick.emit(i);
  }

}
