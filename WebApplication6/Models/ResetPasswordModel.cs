using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Web;


namespace WebApplication6.Models
{
    public class ResetPasswordModel
    {
        [Required(ErrorMessage = "New password required", AllowEmptyStrings = false)]
        [RegularExpression(@"^(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$", ErrorMessage = "Password must contain one uppercase(A) one lowercase(a) one number(1) and one special character(@) ")]
        [StringLength(18, ErrorMessage = "The {0} must be at least {2} characters long.", MinimumLength = 6)]
       
        [DataType(DataType.Password)]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "New password and confirm password does not match")]
        public string ConfirmPassword { get; set; }

        public long id { get; set; }
        [Required]
        public string ResetCode { get; set; }
    }
}