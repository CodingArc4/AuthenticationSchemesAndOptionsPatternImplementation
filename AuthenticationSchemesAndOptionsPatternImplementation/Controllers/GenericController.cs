﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationSchemesAndOptionsPatternImplementation.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class GenericController : ControllerBase
    {
        [HttpGet("GetByCookie")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetByCookie()
        {  
            return Ok("accessed by cookie.");
        }

        [HttpGet("GetByJWT")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetByJWT()
        {
            return Ok("This endpoint got accessed by jwt.");
        }
    }
}