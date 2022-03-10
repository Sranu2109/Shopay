using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Core.Entities;
using Core.Interfaces;
using Infrastructure.Data;
using Microsoft.AspNetCore.Mvc;
using OfficeOpenXml;

namespace API.Controllers
{
    public class ImportController : Controller
    {
        private readonly StoreContext _context;
        private readonly IWebHostEnvironment _webHostEnvironment;
        private readonly IGenericRepository<SellerProductlist> _sellerproductrepo;
        private readonly IConfiguration _config;

        public ImportController(IGenericRepository<SellerProductlist> sellerproductrepo, StoreContext context, IWebHostEnvironment webHostEnvironment, IConfiguration config)
        {
            _config = config;
            _sellerproductrepo = sellerproductrepo;
            _webHostEnvironment = webHostEnvironment;
            _context = context;

        }
        
        [HttpPost("ProductUpload")]
        public async Task<List<Product>> ProductUpload(IFormFile file)
        //, List<IFormFile> files,string sellername)
        {
            var list=new List<Product>();
            using(var stream = new MemoryStream())
            {
                await file.CopyToAsync(stream);
                using(var package = new ExcelPackage(stream))
                {
                    ExcelWorksheet worksheet= package.Workbook.Worksheets[0];
                    var rowcount = worksheet.Dimension.Rows;
                    for(int row = 2;row<rowcount;row++)
                    {
                        list.Add(new Product{
                            //Id=Convert.ToInt32(worksheet.Cells[row,0].Value),
                            Name = worksheet.Cells[row,1].Value.ToString().Trim(),
                            Description =worksheet.Cells[row,2].Value.ToString().Trim(),
                            Price=Convert.ToDecimal(worksheet.Cells[row,3].Value),
                            RentedPrice = Convert.ToDecimal(worksheet.Cells[row,4].Value),
                            PictureUrl =worksheet.Cells[row,5].Value.ToString().Trim(),
                            ProductTypeId=Convert.ToInt32(worksheet.Cells[row,6].Value),
                            ProductBrandId=Convert.ToInt32(worksheet.Cells[row,7].Value),
                            CategoryId=Convert.ToInt32(worksheet.Cells[row,8].Value),

                            
                        });
                    }
                }
            }
            var sellername = "ram";
            foreach(var x in list)
            {
              //var email = HttpContext.User.RetrieveEmailFromPrincipal();
              
              await  _context.Products.AddAsync(x);
              await _context.SaveChangesAsync();
              var seller=new SellerProductlist();
              seller.Id=x.Id;
              seller.productid=x.Id;
              seller.sellername=sellername;
              await _context.productlists.AddAsync(seller);
              await _context.SaveChangesAsync();
            }

            return list;
        }



    [HttpPost("UploadImage"), DisableRequestSizeLimit]
    public IActionResult UploadImage()
    {
        try
        {
            var images  = Request.Form.Files;

            foreach (var file in images)
            {
                
            
            var FilePath = _config.GetValue<string>("FilePath");
            var pathToSave = Path.Combine(Directory.GetCurrentDirectory(), file.FileName);

            if(file.Length > 0)
            {
                var fileName = ContentDispositionHeaderValue.Parse(file.ContentDisposition).FileName.Trim('"');
                var fullPath = Path.Combine(FilePath, file.FileName);
                var dbPath = Path.Combine(file.FileName, fileName);
                using(var stream = new FileStream(fullPath, FileMode.Create))
                {
                    file.CopyTo(stream);
                }
              //  return Ok(new { dbPath });
            }
            else{
             //   return BadRequest();
            }
            }
            return Ok();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"Internal server error : {ex}");
        }
    }
    }
}