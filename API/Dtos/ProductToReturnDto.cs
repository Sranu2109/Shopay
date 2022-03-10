namespace API.Dtos
{
    public class ProductToReturnDto
    {
        public int Id { get; set; }
        public string Name { get; set; }   //property to fetch details into database
        public string  Description { get; set; }
        public decimal Price { get; set; }
        public decimal RentedPrice { get; set; }
        public string PictureUrl { get; set; }

        // public int TotalStock { get; set; }
        public string ProductType { get; set; }     //related entities
        public string ProductBrand { get; set; }     //related entities
        public string Category { get; set; }          //related entities
    }
}