﻿using System.ComponentModel.DataAnnotations;

namespace AuthenticationSchemesAndOptionsPatternImplementation.ViewModels
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }
        //public string  Role { get; set; }
    }
}
