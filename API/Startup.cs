using API.Extensions;
using API.Helpers;
using API.Middleware;
using Infrastructure.Data;
using Infrastructure.Identity;
using Infrastructure.SellerIdentity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.FileProviders;
using StackExchange.Redis;

namespace API
{
    public class Startup
    {
        private readonly IConfiguration _config;
        public Startup(IConfiguration config)    //constructor for access to our configuration that's being injected to our startup class
        {
            _config = config;
        }


        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)    //method to configure services
        {

           // services.AddControllersWithViews();

            services.AddAutoMapper(typeof(MappingProfiles));

            services.AddControllers();          //service to add controllers

            services.AddDbContext<StoreContext>( x => 
                    x.UseNpgsql(_config.GetConnectionString("DefaultConnection")));

            services.AddDbContext<AppIdentityDbContext> (x =>
            {
                x.UseNpgsql(_config.GetConnectionString("IdentityConnection"));
            });

            services.AddDbContext<AppSellerIdentityDbContext> (x =>
            {
                x.UseNpgsql(_config.GetConnectionString("SellerIdentityConnection"));
            });

            services.AddSingleton<IConnectionMultiplexer>(c =>{              //connection string to connect redis
                var configuration = ConfigurationOptions.Parse(_config.GetConnectionString("Redis"), true);
                return ConnectionMultiplexer.Connect(configuration);
            });

            services.AddApplicationServices();

            services.AddIdentityServices(_config);

            services.AddSellerIdentityServices();

            services.AddSwaggerDocumentation();

            services.AddCors(opt =>
            {
                opt.AddPolicy("CorsPolicy", policy =>
                { 
                    policy.AllowAnyHeader().AllowAnyMethod().WithOrigins("https://localhost:4200");
                });
            });
            
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            app.UseMiddleware<ExceptionMiddleware>();  //commenting UseDeveloperExceptionPage and add this

            // if (env.IsDevelopment())           //check if we are in development mode
            // {
            //     //app.UseDeveloperExceptionPage();      //developer encounters exception
            //     app.UseSwagger();
            //     app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "API v1"));
            // }

            app.UseStatusCodePagesWithReExecute("/errors/{0}");    //middeleware for not found endpoint error handler

            app.UseHttpsRedirection();     //middleware

            app.UseRouting();              //middleware
            app.UseStaticFiles();

            app.UseStaticFiles(new StaticFileOptions
            {
                FileProvider = new PhysicalFileProvider(
                    Path.Combine(Directory.GetCurrentDirectory(), "Content")
                ), RequestPath= "/content"
            });

            app.UseCors("CorsPolicy");

            app.UseAuthentication();

            app.UseAuthorization();         //middleware

            app.UseSwaggerDocumentation();

            app.UseEndpoints(endpoints =>           //middleware to know which endpoints are available inside our controller so that they can be routed to
            {
                endpoints.MapControllers();
                endpoints.MapFallbackToController("Index", "Fallback");
            });
        }
    }
}
