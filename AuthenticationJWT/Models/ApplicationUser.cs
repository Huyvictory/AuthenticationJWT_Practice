using AuthenticationJWT.Entities;
using Microsoft.AspNetCore.Identity;

namespace AuthenticationJWT.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public List<RefreshToken> RefreshToken { get; set; }
    }
}
