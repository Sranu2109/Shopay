namespace Core.Entities
{
    public class CustomerBasket
    {
        public CustomerBasket()  //empty constructor
        {
        }

        public CustomerBasket(string id)
        {
            Id = id;
        }

        public string Id { get; set; }  //customer generates 
        public List<BasketItem> Items { get; set; } = new List<BasketItem>();   //customer generates new list of basket items

    }
}