import { Component, OnInit } from '@angular/core';
import { AccountService } from './account/account.service';
import { BasketService } from './basket/basket.service';
import { SellerAccountService } from './seller-account/seller-account.service';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.scss']
})
export class AppComponent implements OnInit {
  title = 'Shopay';

  constructor(private basketService: BasketService, private accountService: AccountService, private sellerAccountService: SellerAccountService) { }

  ngOnInit(): void {
    this.loadBasket();
    this.loadCurrentUser();
    //this.loadCurrentSeller();
  }

  loadCurrentUser() {
    const token = localStorage.getItem('token');
    this.accountService.loadCurrentUser(token).subscribe(() => {
      console.log('loaded user');
    }, error => {
      console.log(error);
    })
  }

  loadBasket() {
    const basketId = localStorage.getItem('basket_id');
    if (basketId) {
      this.basketService.getBasket(basketId).subscribe(() => {
        console.log('initialised basket');
      }, error => {
        console.log(error);
      })
    }
  }

  // loadCurrentSeller() {
  //   const email = localStorage.getItem('email');
  //   this.sellerAccountService.loadCurrentSeller(email).subscribe(() => {
  //     console.log('loaded user');
  //   }, error => {
  //     console.log(error);
  //   })
  // }
}