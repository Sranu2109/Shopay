import { Component, OnInit } from '@angular/core';
import { FormControl, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { SellerAccountService } from '../seller-account.service';

@Component({
  selector: 'app-seller-login',
  templateUrl: './seller-login.component.html',
  styleUrls: ['./seller-login.component.scss']
})
export class SellerLoginComponent implements OnInit {
  loginForm: FormGroup;

  constructor(private sellerAccountService: SellerAccountService, private router: Router, private toastr: ToastrService) { }

  ngOnInit(): void {
    this.createSellerLoginForm();
  }

  createSellerLoginForm(){
    this.loginForm = new FormGroup({
      email: new FormControl('', [Validators.required, Validators
        .pattern('^[\\w-\\.]+@([\\w-]+\\.)+[\\w-]{2,4}$')]),
      password: new FormControl('', Validators.required)
    });
  }

  onSellerSubmit(){
    this.sellerAccountService.sellerlogin(this.loginForm.value).subscribe(() => {
      this.router.navigateByUrl('/sellerhome');
      this.toastr.success("Seller Logged in successfully");
    }, error => {
      console.log(error);
    })
  }

}
