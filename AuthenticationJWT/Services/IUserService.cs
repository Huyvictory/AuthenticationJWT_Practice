using AuthenticationJWT.Models;

namespace AuthenticationJWT.Services
{
    public interface IUserService
    {
        Task<string> RegisterAsync(RegisterUserModel model);
        Task<ResponseAuthenticationModel> GetTokenAsync(SignInModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
    }
}
