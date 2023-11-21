using Microsoft.AspNetCore.Identity;

namespace AuthenticationSchemesAndOptionsPatternImplementation.Model
{
    public class ApplicationUser:IdentityUser
    {
        public string Name { get; set; }

    }
}
