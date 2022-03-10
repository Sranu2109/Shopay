using Core.Entities;
using Core.Entities.OrderAggregate;
using Core.Interfaces;
using Core.Specifications;

namespace Infrastructure.Services
{
    public class OrderService : IOrderService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IBasketRepository _basketRepo;
        public OrderService( IBasketRepository basketRepo, IUnitOfWork unitOfWork)                     //creating repositories basket is using different db so its not part of our context in unit of work
        {
            _unitOfWork = unitOfWork;
            _basketRepo = basketRepo;
        }

        //For Order
        public async Task<Order> CreateOrderAsync(string buyerEmail, int deliveryMethodId, string basketId, Address shippingAddress)
        {
            //get basket from the basket repo
            var basket = await _basketRepo.GetBasketAsync(basketId);

            //get items from the product repo
            var items = new List<OrderItem>();
            foreach (var item in basket.Items)
            {
                var productItem = await _unitOfWork.Repository<Product>().GetByIdAsync(item.Id);
                var itemOrdered = new ProductItemOrdered(productItem.Id, productItem.Name, productItem.PictureUrl);
                var orderItem = new OrderItem(itemOrdered, productItem.Price, item.Quantity);
                items.Add(orderItem);
            }
            //get delivery method from repo
            var deliveryMethod = await _unitOfWork.Repository<DeliveryMethod>().GetByIdAsync(deliveryMethodId);

            //calc subtotal
            var pricesubtotal = items.Sum(item => item.Price * item.Quantity);

            //create order
            var order = new Order(items, buyerEmail, shippingAddress, deliveryMethod, pricesubtotal);
        _unitOfWork.Repository<Order>().Add(order);

            //save to db
            var result = await _unitOfWork.Complete();

            if(result <= 0) return null;

            //delete basket if order is made
            await _basketRepo.DeleteBasketAsync(basketId);

            //return order
            return order;
            
        }

        //implementing the order get methods

        public async Task<IReadOnlyList<DeliveryMethod>> GetDeliveryMethodsAsync()
        {
            return await _unitOfWork.Repository<DeliveryMethod>().ListAllAsync();
        }

        public async Task<Order> GetOrderByIdAsync(int id, string buyerEmail)
        {
            var spec = new OrdersWithitemsAndOrdering(id, buyerEmail);

            return await _unitOfWork.Repository<Order>().GetEntityWithSpec(spec);
        }

        public async Task<IReadOnlyList<Order>> GetOrdersForUserAsync(string buyerEmail)
        {
            var spec = new OrdersWithitemsAndOrdering(buyerEmail);

            return await _unitOfWork.Repository<Order>().ListAsync(spec);
        }
    }
}