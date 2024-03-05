using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationJWT.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class SecuredController : Controller
    {
        [HttpGet]
        public async Task<IActionResult> GetSecuredData()
        {
            return Ok("This Secured Data is available only for Authenticated Users.");
        }
    }
}
