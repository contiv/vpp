import { Component, OnInit, Input, ViewEncapsulation } from '@angular/core';
import { FormObject } from '../interfaces/form-object';

@Component({
  selector: 'app-form',
  templateUrl: './form.component.html',
  styleUrls: ['./form.component.css'],
  encapsulation: ViewEncapsulation.None
})
export class FormComponent implements OnInit {

  @Input() data: FormObject[];

  constructor() { }

  ngOnInit() {
  }

}
