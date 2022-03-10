using System.ComponentModel.DataAnnotations;

namespace API.Dtos
{
    public class SellerRegisterDto
    {
        [Required]
        public string SellerName { get; set; }

        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [RegularExpression("(?=^.{6,10}$)(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&amp;*()_+}{&quot;:;'?/&gt;.&lt;,])(?!.*\\s).*$",
        ErrorMessage="Password must have 1 UpperCase ,1 Lowercase, 1 number, 1 non alphanumeric and at 6 characters")]
        public string Password { get; set; }
    }
}