import { Injectable } from '@angular/core';
import { Subject } from 'rxjs';
import { SvgTransform } from '../topology/interfaces/svg-transform';
import { Point } from '../topology/interfaces/point';

@Injectable({
  providedIn: 'root'
})
export class CoreService {

  public isWorkingSubject = new Subject<boolean>();

  constructor() { }
  /**
   * Extract values from string
   * Match `property1(..values) property2(..values) ...`
   */
  public parseTransform(str: string): SvgTransform {
    if (!str) {
      return {
        translate: [0, 0],
        scale: [1]
      };
    }

    const obj = {};
    const properties = str.match(/(\w+\((\-?\d+\.?\d*e?\-?\d*,?)+\))+/g);

    properties.forEach(element => {
      const match = element.match(/[\w\.\-]+/g);

      const matchArr = match.map(
        (value, i) => {
          if (i !== 0) {
            return parseFloat(value);
          } else {
            return value;
          }
        }
      );

      obj[matchArr.shift()] = matchArr;
    });

    return obj;
  }

  /**
   * Generate random string
   */
  public generateRandomString(length: number): string {
    return Math.random().toString(36).substr(2, length);
  }

  public generateColor() {
    return '#' + Math.random().toString(16).substr(-6);
  }

  public parsePoint(str: string): Point {
    const arr = str.split(' ');

    return {
      x: parseInt(arr[0], 10),
      y: parseInt(arr[1], 10)
    };
  }

}
