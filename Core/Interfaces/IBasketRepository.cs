using Core.Entities;

namespace Core.Interfaces
{
    public interface IBasketRepository
    {
        //methods to create, update and delete basket
        Task<CustomerBasket> GetBasketAsync(string basketId);
        Task<CustomerBasket> UpdateBasketAsync(CustomerBasket basket);
        Task<bool> DeleteBasketAsync(string basketId);
        
    }
}