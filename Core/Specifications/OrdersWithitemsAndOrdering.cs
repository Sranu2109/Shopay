using Core.Entities.OrderAggregate;

namespace Core.Specifications
{
    public class OrdersWithitemsAndOrdering : BaseSpecification<Order>
    {
        public OrdersWithitemsAndOrdering(string email) : base(o => o.BuyerEmail == email)
        {
            AddInclude(o => o.OrderItems);
            AddInclude(o => o.DeliveryMethod);
            AddOrderByDescending(o => o.OrderDate);
        }

        public OrdersWithitemsAndOrdering(int id, string email ) 
        : base(o => o.Id == id && o.BuyerEmail == email)          //for individual order
        {
            AddInclude(o => o.OrderItems);
            AddInclude(o => o.DeliveryMethod);
        }
    }
}