using Microsoft.AspNetCore.Identity;

namespace Core.Entities.SellerIdentity
{
    public class AppSeller : IdentityUser
    {
        public string SellerName { get; set; }
    }
}