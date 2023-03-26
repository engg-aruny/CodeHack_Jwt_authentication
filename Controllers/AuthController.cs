using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CodeHack_Jwt_authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] UserModel login)
        {
            IActionResult response = Unauthorized();
            var user = new UserModel().AuthenticateUser(login);

            if (user != null)
            {
                var tokenString = JwtTokenHandler.GenerateJSONWebToken(user, _configuration);
                response = Ok(new { token = tokenString });
            }

            return response;
        }
    }
}
