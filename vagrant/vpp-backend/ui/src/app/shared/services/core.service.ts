import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class CoreService {

  constructor() { }

  /**
   * Create list of objects based on type
   */
  public extractListData<T>(response: Array<any>, type: { new (value: any): T }): Array<T> {
    return response.map(
      data => {
        return new type(data);
      }
    );
  }

  public extractObjectData<T>(response: any, type: { new (value: any): T }): T {
    return new type(response);
  }

  public extractObjectDataToArray<T>(response: any, type: { new (value: any): T }): Array<T> {
    return Object.keys(response).map(
      key => {
        response[key]._key = key;
        return new type(response[key]);
      }
    );
  }

  /**
   * Generate random string
   */
  public generateRandomString(length: number): string {
    return Math.random().toString(36).substr(2, length);
  }

  public getPointOnCircle(radius: number, angleDeg: number, origin: {x: number, y: number}): {x: number, y: number} {
    return {
      x: (radius * Math.cos(angleDeg * Math.PI / 180)) + origin.x,
      y: (radius * Math.sin(angleDeg * Math.PI / 180)) + origin.y
    };
  }

  public getPointOnEllipse(a: number, b: number, angleDeg: number, origin: {x: number, y: number}): {x: number, y: number} {
    return {
      x: (a * Math.cos(angleDeg * Math.PI / 180)) + origin.x,
      y: (b * Math.sin(angleDeg * Math.PI / 180)) + origin.y
    };
  }
}
