using AuthenticationSchemesAndOptionsPatternImplementation.Data;
using AuthenticationSchemesAndOptionsPatternImplementation.Model;
using AuthenticationSchemesAndOptionsPatternImplementation.ViewModels;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationSchemesAndOptionsPatternImplementation.OptionsSettings;
using Microsoft.Extensions.Options;

namespace AuthenticationSchemesAndOptionsPatternImplementation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly JwtSettings _jwtSettings;

        public AccountsController(ApplicationDbContext context, SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,IOptions<JwtSettings> jwtSettings)
        {
            _context = context;
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _jwtSettings = jwtSettings.Value;
        }

        //Generate JWT Token When Logged In
        [HttpPost("loginJWT")]
        public async Task<IActionResult> LoginJWT([FromBody] LoginViewModel loginViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginViewModel.Email);

                var result = await _signInManager.CheckPasswordSignInAsync(user, loginViewModel.Password, true);

                if (user != null)
                {
                    if (result.Succeeded)
                    {
                        var token = GenerateJwtToken(user);
                        return Ok(new { token });
                    }
                }
                return BadRequest(new { message = "Invalid login attempt." });
            }
            return BadRequest(new { message = "Invalid model state" });
        }


        //Generate Cookies When Logged In
        [HttpPost("loginCookies")]
        public async Task<IActionResult> LoginCookies([FromBody] LoginViewModel loginViewModel)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(loginViewModel.Email);


                if (user != null)
                {
                    var userRoles = await _userManager.GetRolesAsync(user);

                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.Email)
                    };

                    foreach (var role in userRoles)
                    {
                        claims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var claimsIdentity = new ClaimsIdentity(
                        claims, CookieAuthenticationDefaults.AuthenticationScheme);

                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        AllowRefresh = true,
                        ExpiresUtc = DateTime.UtcNow.AddDays(1)
                    };

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    return Ok(new { message = "Login successful." });
                }

                return BadRequest(new { message = "Invalid login attempt." });
            }

            return BadRequest(new { message = "Invalid model state" });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    Name = model.Name,
                };

                var result = await _userManager.CreateAsync(user, model.Password);

                if (result.Succeeded)
                {
                    // Check if the role exists, and create it if it doesn't
                    if (!await _roleManager.RoleExistsAsync(model.RoleName))
                    {
                        await _roleManager.CreateAsync(new IdentityRole(model.RoleName));
                    }

                    await _userManager.AddToRoleAsync(user, model.RoleName);
                    return Ok("Registration is successful.");
                }
                return BadRequest(new { errors = result.Errors });
            }
            return BadRequest(new { message = "Invalid model state" });
        }

        //Generate Jwt Token
        [HttpGet]
        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);

            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, user.Email)
            };

            foreach (var role in roles.ToList())
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Token));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                    claims: claims,
                    issuer: _jwtSettings.ValidIssuer,
                    audience: _jwtSettings.ValidAudience,
                    expires: DateTime.Now.AddDays(1),
                    signingCredentials: cred
                );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
    }
}
