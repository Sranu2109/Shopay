import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SellerLoginComponent } from './seller-login/seller-login.component';
import { SellerRegisterComponent } from './seller-register/seller-register.component';
import { SellerAccountRoutingModule } from './seller-account-routing.module';
import { SharedModule } from '../shared/shared.module';



@NgModule({
  declarations: [
    SellerLoginComponent,
    SellerRegisterComponent
  ],
  imports: [
    CommonModule,
    SellerAccountRoutingModule,
    SharedModule
  ]
})
export class SellerAccountModule { }
