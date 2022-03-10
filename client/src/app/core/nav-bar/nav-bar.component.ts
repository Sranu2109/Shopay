import { Component, OnInit } from '@angular/core';
import { Observable } from 'rxjs';
import { AccountService } from 'src/app/account/account.service';
import { BasketService } from 'src/app/basket/basket.service';
import { SellerAccountService } from 'src/app/seller-account/seller-account.service';
import { IBasket } from 'src/app/shared/models/basket';
import { ISeller } from 'src/app/shared/models/seller';
import { IUser } from 'src/app/shared/models/user';

@Component({
  selector: 'app-nav-bar',
  templateUrl: './nav-bar.component.html',
  styleUrls: ['./nav-bar.component.scss']
})
export class NavBarComponent implements OnInit {
  basket$: Observable<IBasket>;
  currentUser$: Observable<IUser>;
  currentSeller$: Observable<ISeller>;

  constructor(private basketService: BasketService, private accountService: AccountService, private sellerAccountService: SellerAccountService) { }

  ngOnInit(): void {
    this.basket$ = this.basketService.basket$;
    this.currentUser$ = this.accountService.currentUser$;
    this.currentSeller$ = this.sellerAccountService.currentSeller$;
  }

  logout() {
    this.accountService.logout();
  }

  sellerlogout(){
    this.sellerAccountService.sellerlogout();
  }

}