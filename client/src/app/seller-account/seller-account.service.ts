import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Router } from '@angular/router';
import { map, of, ReplaySubject } from 'rxjs';
import { environment } from 'src/environments/environment';
import { ISeller } from '../shared/models/seller';

@Injectable({
  providedIn: 'root'
})
export class SellerAccountService {
  baseUrl = environment.apiUrl;
  private currentUserSource = new ReplaySubject<ISeller>(1);
  currentSeller$ = this.currentUserSource.asObservable();

  constructor(private http: HttpClient, private router: Router) { }


  // loadCurrentSeller(email: string) {
  //   if (email === null) {
  //     this.currentUserSource.next(null);
  //     return of(null);
  //   }

  //   let headers = new HttpHeaders();
  //   headers = headers.set('Authorization', `Bearer ${email}`);

  //   return this.http.get(this.baseUrl + 'Seller', {headers}).pipe(
  //     map((seller: ISeller) => {
  //       if (seller) {
  //         localStorage.setItem('email', seller.email);
  //         this.currentUserSource.next(seller);
  //       }
  //     })
  //   )
  // }

  sellerlogin(values: any){
    return this.http.post(this.baseUrl + 'Seller/sellerlogin', values).pipe(
      map((seller: ISeller) => {
        if(seller){
          localStorage.setItem('email',seller.email);
          this.currentUserSource.next(seller);
        }
      })
    );
  }

  sellerregister(values: any) {
    return this.http.post(this.baseUrl + 'Seller/sellerregister', values).pipe(
      map((seller: ISeller) => {
        if(seller){
          localStorage.setItem('email', seller.email);
          this.currentUserSource.next(seller);
        }
      })
    );
  }

  sellerlogout(){
    localStorage.removeItem('email');
    this.currentUserSource.next(null);
    this.router.navigateByUrl('/');
  }

  checkEmailExists(email: string){
    return this.http.get(this.baseUrl + 'Seller/emailexists?email=' + email);
  }

}
