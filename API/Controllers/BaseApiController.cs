using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    [ApiController]     //saves us from manually checking to see if there is anyvalidation errors
    [Route("api/[controller]")]  
    public class BaseApiController : ControllerBase
    {
        
    }
}