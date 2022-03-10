import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { SellerhomeComponent } from './sellerhome.component';
import { SharedModule } from '../shared/shared.module';
import { UploadImageComponent } from '../upload-image/upload-image.component';
import { ExcelsheetComponent } from '../excelsheet/excelsheet.component';



@NgModule({
  declarations: [
    SellerhomeComponent,
    UploadImageComponent,
    ExcelsheetComponent
  ],
  imports: [
    CommonModule,
    SharedModule
  ],
  exports: [SellerhomeComponent]
})
export class SellerhomeModule { }
