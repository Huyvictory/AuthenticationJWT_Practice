using AuthenticationJWT.Constants;
using AuthenticationJWT.Models;
using AuthenticationJWT.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace AuthenticationJWT.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWT _jwt;
        public UserService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWT> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        public async Task<string> RegisterAsync(RegisterUserModel model)
        {
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };
            var userWithSameEmail = await _userManager.FindByEmailAsync(model.Email);
            if (userWithSameEmail == null)
            {
                try
                {
                    await _userManager.CreateAsync(user, model.Password);
                    await _userManager.AddToRoleAsync(user, Authorization.default_role.ToString());
                    return $"User Registered with user name {user.UserName}";
                }
                catch (Exception ex)
                {
                    return $"{ex}";
                }
            }
            else
            {
                return $"Email {user.Email} is already registered.";
            }
        }
    }
}
