using Core.Entities;

namespace Core.Specifications
{
    public class ProductsWithTypesBrandsAndCategoriesSpecification : BaseSpecification<Product>
    {
        public ProductsWithTypesBrandsAndCategoriesSpecification(ProductSpecParams productParams)
            : base(x =>
                (string.IsNullOrEmpty(productParams.Search) || x.Name.ToLower().Contains(productParams.Search)) &&
                (!productParams.BrandId.HasValue || x.ProductBrandId == productParams.BrandId) &&
                (!productParams.TypeId.HasValue || x.ProductTypeId == productParams.TypeId) &&
                (!productParams.CategoryId.HasValue || x.CategoryId == productParams.CategoryId)
                )
        {
            AddInclude(x => x.ProductType);
            AddInclude(x => x.ProductBrand);
            AddInclude(x => x.Category);
            AddOrderBy(x => x.Name);
            ApplyPaging(productParams.PageSize*(productParams.PageIndex -1 ), productParams.PageSize);  //for skip property

            if(!string.IsNullOrEmpty(productParams.Sort))
            {
                switch(productParams.Sort)
                {
                    case "priceAsc":
                        AddOrderBy(p => p.Price);
                        break;
                    case "priceDesc":
                        AddOrderByDescending(p => p.Price);
                        break;
                    case "rentedPriceAsc":
                        AddOrderBy(p => p.RentedPrice);
                        break;
                    case "rentedPriceDesc":
                        AddOrderByDescending(p => p.RentedPrice);
                        break;
                    default:
                        AddOrderBy(n =>n.Name);
                        break;
                }
            }
        }

        public ProductsWithTypesBrandsAndCategoriesSpecification(int id) : base(x => x.Id ==id)
        {
            AddInclude(x => x.ProductType);
            AddInclude(x => x.ProductBrand);
            AddInclude(x => x.Category);
        }
    }
}