
using API.Dtos;
using API.Errors;
using Core.Entities.SellerIdentity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    public class SellerController : BaseApiController
    {
        private readonly UserManager<AppSeller> _userManager;
        private readonly SignInManager<AppSeller> _signInManager;
        public SellerController(UserManager<AppSeller> userManager, SignInManager<AppSeller> signInManager)
        {
            _signInManager = signInManager;
            _userManager = userManager;

        }

        [HttpGet("emailexists")]
        public async Task<ActionResult<bool>> CheckEmailExistsAsync([FromQuery] string email)
        {
            return await _userManager.FindByEmailAsync(email) != null;
        }

        [HttpPost("sellerlogin")]
        public async Task<ActionResult<SellerDto>> SellerLogin(SellerLoginDto sellerLoginDto)
        {
            var seller = await _userManager.FindByEmailAsync(sellerLoginDto.Email);

            if(seller == null) return Unauthorized(new ApiResponse(401));

            var result = await _signInManager.CheckPasswordSignInAsync(seller, sellerLoginDto.Password, false);

            if(!result.Succeeded) return Unauthorized(new ApiResponse(401));

            return new SellerDto
            {
                Email = seller.Email,
                SellerName = seller.SellerName

            };
        }


        [HttpPost("sellerregister")]
        public async Task<ActionResult<SellerDto>> SellerRegister(SellerRegisterDto sellerRegisterDto) 
        {
            if (CheckEmailExistsAsync(sellerRegisterDto.Email).Result.Value)
            {
                return new BadRequestObjectResult(new ApiValidationErrorResponse { Errors = new[] { "Email address is in Use" } });
            }

            var seller = new AppSeller
            {
                SellerName = sellerRegisterDto.SellerName,
                Email = sellerRegisterDto.Email,
                UserName = sellerRegisterDto.Email
            };

            var result = await _userManager.CreateAsync(seller, sellerRegisterDto.Password);

            if(!result.Succeeded) return BadRequest(new ApiResponse(400));

            return new SellerDto
            {
                SellerName = seller.SellerName,
                Email = seller.Email
            };
        }
    }
}