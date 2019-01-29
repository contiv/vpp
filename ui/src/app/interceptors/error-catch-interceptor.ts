import { Injectable } from '@angular/core';
import {
  HttpEvent, HttpInterceptor, HttpHandler, HttpRequest, HttpResponse, HttpErrorResponse
} from '@angular/common/http';

import { Observable, throwError, of } from 'rxjs';
import { catchError, map, switchMap } from 'rxjs/operators';

@Injectable()
export class ErrorCatchInterceptor implements HttpInterceptor {

  intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {

    return next.handle(request);
    // return next.handle(request).pipe(
    //   catchError((error: HttpErrorResponse) => {
    //     return next.handle(request).pipe(
    //       switchMap(() => of(null))
    //     );
    //     return throwError(error);
    //     console.log(error);
    //     // return error.status;
    //   })
    // );
  }
}
