using Core.Entities.SellerIdentity;
using Microsoft.AspNetCore.Identity;

namespace Infrastructure.SellerIdentity
{
    public class AppSellerIdentityDbContextSeed
    {
        public static async Task SeedSellerAsync(UserManager<AppSeller> userManager)
        {
            if(!userManager.Users.Any())
            {
                var seller = new AppSeller
                {
                    SellerName = "Bob",
                    Email = "bob2@test.com",
                    UserName = "bob2@test.com"
                };

                await userManager.CreateAsync(seller, "Pa$$w0rd");
            }
        }
    }
}