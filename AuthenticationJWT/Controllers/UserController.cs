using AuthenticationJWT.Models;
using AuthenticationJWT.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : Controller
    {
        private readonly IUserService _userService;
        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<ActionResult> RegisterAsync(RegisterUserModel model)
        {
            var result = await _userService.RegisterAsync(model);
            return Ok(result);
        }
    }
}
