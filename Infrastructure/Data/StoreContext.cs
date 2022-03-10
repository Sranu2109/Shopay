
using System.Reflection;
using Core.Entities;
using Core.Entities.OrderAggregate;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Infrastructure.Data
{
    public class StoreContext : DbContext     //after installing nuget package manager for entityframework for sqlite
    {
        public StoreContext(DbContextOptions<StoreContext> options) : base(options)
        {
        }

        public DbSet<Product> Products { get; set; }         //property where we create a database of products
        public DbSet<ProductType> ProductTypes { get; set; }     //database of product types
        public DbSet<ProductBrand> ProductBrands { get; set; }    //database of product brands
        public DbSet<Category> Categories { get; set; }    //database of product category

        public DbSet<Order> Orders { get; set; }          // database of orders
        public DbSet<OrderItem> OrderItems { get; set; }   //databse of orderItems
        public DbSet<DeliveryMethod> DeliveryMethods { get; set; }    //database of deliveryMethods
        public DbSet<SellerProductlist> productlists {get;set;}   // database for the seller with its product info

        protected override void OnModelCreating(ModelBuilder modelBuilder)   //method
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.ApplyConfigurationsFromAssembly(Assembly.GetExecutingAssembly());

        if (Database.ProviderName == "Npgsql.EntityFrameworkCore.PostgreSQL")    //condition for decimal price demerit of sqlite
        {
            foreach (var entityType in modelBuilder.Model.GetEntityTypes())
            {
                var properties = entityType.ClrType.GetProperties().Where(p => p.PropertyType == typeof(decimal));
                var dateTimeProperties = entityType.ClrType.GetProperties().Where(p => p.PropertyType == typeof(DateTimeOffset));

                foreach (var property in properties)
                {
                    modelBuilder.Entity(entityType.Name).Property(property.Name).HasConversion<double>();
                }

                foreach (var property in dateTimeProperties)
                {
                    modelBuilder.Entity(entityType.Name).Property(property.Name).HasConversion(new DateTimeOffsetToBinaryConverter());
                }
            }
        }

        }
    }
}