using System.Text.Json;
using Core.Entities;
using Core.Interfaces;
using StackExchange.Redis;

namespace Infrastructure.Data
{
    public class BasketRepository : IBasketRepository
    {
        private readonly IDatabase _database;
        public BasketRepository(IConnectionMultiplexer redis)
        {
            _database =redis.GetDatabase();        //connection to our database
        }

        public async Task<bool> DeleteBasketAsync(string basketId)
        {
            return await _database.KeyDeleteAsync(basketId);
        }

        public async Task<CustomerBasket> GetBasketAsync(string basketId)
        {
            var data = await _database.StringGetAsync(basketId);    //get basket with the basketid

            return data.IsNullOrEmpty ? null : JsonSerializer.Deserialize<CustomerBasket>(data);  //if data then add serialize else return null
        }

        public async Task<CustomerBasket> UpdateBasketAsync(CustomerBasket basket)  //replace existing basket with a new one
        {
            var created = await _database.StringSetAsync(basket.Id, 
            JsonSerializer.Serialize(basket), TimeSpan.FromDays(30));    //basket to hang around for a timespan of 30 days

            if(!created) return null;

            return await GetBasketAsync(basket.Id);
        }
    }
}