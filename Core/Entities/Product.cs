namespace Core.Entities
{
    public class Product : BaseEntity
    {
        public string Name { get; set; }   //property to fetch details into database
        public string  Description { get; set; }
        public decimal Price { get; set; }
        public decimal RentedPrice { get; set; }
        public string PictureUrl { get; set; }
        public ProductType ProductType { get; set; }     //related entities
        public int ProductTypeId { get; set; }
        public ProductBrand ProductBrand { get; set; }     //related entities
        public int ProductBrandId { get; set; }
        public Category Category { get; set; }          //related entities
        public int CategoryId { get; set; }

    }
}