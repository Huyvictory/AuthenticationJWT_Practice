using AuthenticationJWT.Models;

namespace AuthenticationJWT.Services
{
    public interface IUserService
    {
        Task<string> RegisterAsync(RegisterUserModel model);
    }
}
