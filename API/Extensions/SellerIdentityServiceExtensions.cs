using Core.Entities.SellerIdentity;
using Infrastructure.SellerIdentity;
using Microsoft.AspNetCore.Identity;

namespace API.Extensions
{
    public static class SellerIdentityServiceExtensions
    {
        public static IServiceCollection AddSellerIdentityServices(this IServiceCollection services)
        {
            var builder = services.AddIdentityCore<AppSeller>();

            builder = new IdentityBuilder(builder.UserType, builder.Services);
            builder.AddEntityFrameworkStores<AppSellerIdentityDbContext>();
            builder.AddSignInManager<SignInManager<AppSeller>>();

            services.AddAuthentication();

            return services;
        }
        
    }
}