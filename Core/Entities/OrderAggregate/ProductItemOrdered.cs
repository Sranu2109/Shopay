namespace Core.Entities.OrderAggregate
{
    public class ProductItemOrdered  //to save the snapshot of the product item wehen ordered because after sometime the name or image might change
    {
        public ProductItemOrdered()    //since we're using entity framework so we need parameter less constructor as well
        {
        }

        public ProductItemOrdered(int productItemId, string productName, string pictureUrl)
        {
            ProductItemId = productItemId;
            ProductName = productName;
            PictureUrl = pictureUrl;
        }

        public int ProductItemId { get; set; }
        public string ProductName { get; set; }
        public string PictureUrl { get; set; }
    }
}