
using API.Dtos;
using API.Errors;
using API.Helpers;
using AutoMapper;
using Core.Entities;
using Core.Interfaces;
using Core.Specifications;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    // [ApiController]
    // [Route("api/[controller]")]        //adding api/is optional but is conventional
    public class ProductsController : BaseApiController
    {
        private readonly IGenericRepository<Product> _productsRepo;
        private readonly IGenericRepository<ProductBrand> _productBrandRepo;
        private readonly IGenericRepository<ProductType> _productTypeRepo;
        private readonly IGenericRepository<Category> _categoryRepo;
        private readonly IMapper _mapper;
        public ProductsController(IGenericRepository<Product> productsRepo, IGenericRepository<ProductBrand> productBrandRepo, IGenericRepository<ProductType> productTypeRepo, IGenericRepository<Category> categoryRepo, IMapper mapper)         //constructor here StoreContext is the name of the class we want to inject
        {
            _productsRepo = productsRepo;
            _productBrandRepo = productBrandRepo;
            _productTypeRepo = productTypeRepo;
            _categoryRepo = categoryRepo;
            _mapper = mapper;

        }

        [HttpGet]         //adding endpoints
        //public string GetProducts()          //adding methods
        public async Task<ActionResult<Pagination<ProductToReturnDto>>> GetProducts(
            [FromQuery]ProductSpecParams productParams)    //using asynchronus version of this method as this request can take tens of seconds
        {
            var spec = new ProductsWithTypesBrandsAndCategoriesSpecification(productParams);

            var countSpec = new ProductWithFiltersForCountSpecification(productParams);

            var totalItems = await _productsRepo.CountAsync(countSpec);

            var products = await _productsRepo.ListAsync(spec);     //fetches product table from select query of database and stores it in variable

            var data = _mapper.Map<IReadOnlyList<Product>, IReadOnlyList<ProductToReturnDto>>(products);

            return Ok(new Pagination<ProductToReturnDto>(productParams.PageIndex, productParams.PageSize, totalItems, data));
        }   

        [HttpGet("{id}")]           //for single product we have product id

        //Adding attributes to the method
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(ApiResponse), StatusCodes.Status404NotFound)]
        public async Task<ActionResult<ProductToReturnDto>> GetProduct(int id)     //passing parameters to make this method different
        {
            var spec = new ProductsWithTypesBrandsAndCategoriesSpecification(id);

            var product = await _productsRepo.GetEntityWithSpec(spec);   //go & gets our product from database as per id

            if(product == null) return NotFound(new ApiResponse(404));   //to have consistent errors

            return _mapper.Map<Product, ProductToReturnDto>(product);
        }  

        [HttpGet("categories")]  
        public async Task<ActionResult<IReadOnlyList<Category>>> GetCategories()    //method for product category
        {
            return Ok(await _categoryRepo.ListAllAsync());
        }   

        [HttpGet("brands")]  
        public async Task<ActionResult<IReadOnlyList<ProductBrand>>> GetProductBrands()     //method for product brands
        {
            return Ok(await _productBrandRepo.ListAllAsync());
        }

        [HttpGet("types")]  
        public async Task<ActionResult<IReadOnlyList<ProductType>>> GetProductTypes()    //methods for product types
        {
            return Ok(await _productTypeRepo.ListAllAsync());
        }

    }
}