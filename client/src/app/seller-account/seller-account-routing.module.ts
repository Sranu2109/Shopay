import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SellerLoginComponent } from './seller-login/seller-login.component';
import { SellerRegisterComponent } from './seller-register/seller-register.component';
import { RouterModule, Routes } from '@angular/router';

const routes: Routes = [
  {path: 'seller-login', component: SellerLoginComponent},
  {path: 'seller-register', component: SellerRegisterComponent}
];

@NgModule({
  declarations: [],
  imports: [
    RouterModule.forChild(routes)
  ],
  exports: [RouterModule]
})
export class SellerAccountRoutingModule { }
