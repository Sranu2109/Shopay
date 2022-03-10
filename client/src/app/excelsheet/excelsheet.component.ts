import { HttpClient, HttpEventType } from '@angular/common/http';
import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { Event } from 'ngx-bootstrap/utils/facade/browser';
import { environment } from 'src/environments/environment';
//import * as XLSX from 'xlsx';

@Component({
  selector: 'app-excelsheet',
  templateUrl: './excelsheet.component.html',
  styleUrls: ['./excelsheet.component.scss']
})
export class ExcelsheetComponent implements OnInit {
  public progress: number;
  public message: string;
  @Output() public onUploadFinished = new EventEmitter();
  constructor(private http: HttpClient) { }

  ngOnInit(): void {
    
  }
  public uploadFile = (files) => {
    if (files.length === 0) {
      return;
    }
    
    let fileToUpload = <File>files[0];
    const formData = new FormData();
    formData.append('file', fileToUpload, fileToUpload.name);
    
    this.http.post('https://localhost:5001/ProductUpload', formData, {reportProgress: true, observe: 'events'})
   // this.http.get('https://localhost:5001/hritik', {reportProgress: true, observe: 'events'})
      .subscribe(event => {
        if (event.type === HttpEventType.UploadProgress)
          this.progress = Math.round(100 * event.loaded / event.total);
        else if (event.type === HttpEventType.Response) {
          this.message = 'Upload success.';
          this.onUploadFinished.emit(event.body);
        }
      });
  // onFileChange(evt: any) {
  //   const target : DataTransfer =  <DataTransfer>(evt.target);
    
  //   // if (target.files.length !== 1) throw new Error('Cannot use multiple files');

  //   const reader: FileReader = new FileReader();

  //   reader.onload = (e: any) => {
  //     const bstr: string = e.target.result;

  //     const wb: XLSX.WorkBook = XLSX.read(bstr, { type: 'binary' });

  //     const wsname : string = wb.SheetNames[0];

  //     const ws: XLSX.WorkSheet = wb.Sheets[wsname];

  //     console.log(ws);

  //     this.data = (XLSX.utils.sheet_to_json(ws, { header: 1 }));

  //     console.log(this.data);

  //     let x = this.data.slice(1);
  //     // console.log(x);
  //     // console.log("*");
  //     // console.log("*");
  //     // console.log(reader);
  //     // console.log("*");
  //   //this.http.post(this.baseUrl + 'seller/ProductUpload', evt);
    
  //   };
  
    
  //   reader.readAsBinaryString(target.files[0]);
    
  // }
  // hritik()
  // {
  //   this.http.get("https://localhost:5001/api/Account/hritik");
  // }
    }

}