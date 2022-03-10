import { HttpClient, HttpEventType } from '@angular/common/http';
import { Component, EventEmitter, OnInit, Output } from '@angular/core';
import { Event } from 'ngx-bootstrap/utils/facade/browser';
import { environment } from 'src/environments/environment';

@Component({
  selector: 'app-upload-image',
  templateUrl: './upload-image.component.html',
  styleUrls: ['./upload-image.component.scss']
})
export class UploadImageComponent implements OnInit {
  public progress: number;
  public message: string;
  @Output() public onUploadFinished = new EventEmitter();

  constructor(private http: HttpClient) { }

  ngOnInit(): void {
  }

  public uploadFile = (files) => {
    if(files.length === 0) {
      return;
    }

    // let fileToUpload = <File>files;
    const formData = new FormData();
    for(var i=0;i<files.length;i++)
    {
    let fileToUpload = <File>files[i];
    formData.append('file',fileToUpload,fileToUpload.name);
    } 

   
    // formData.append('file', fileToUpload, fileToUpload.name);

    this.http.post('https://localhost:5001/UploadImage', formData, { reportProgress: true, observe: 'events' })
      .subscribe(event => {
        if(event.type === HttpEventType.UploadProgress)
          this.progress = Math.round(100 * event.loaded / event.total);
        else if(event.type === HttpEventType.Response){
          this.message = 'Upload Success.';
          this.onUploadFinished.emit(event.body);
        }
      });
  }

}
