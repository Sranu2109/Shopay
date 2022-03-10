using Core.Entities.SellerIdentity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure.SellerIdentity
{
    public class AppSellerIdentityDbContext : IdentityDbContext<AppSeller>
    {
        public AppSellerIdentityDbContext(DbContextOptions<AppSellerIdentityDbContext> options) : base(options)
        {
        }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
        }
    }
}