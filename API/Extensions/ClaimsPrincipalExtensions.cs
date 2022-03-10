using System.Security.Claims;

namespace API.Extensions
{
    public static class ClaimsPrincipalExtentions
    {
        public static string RetrieveEmailFromPrincipal(this ClaimsPrincipal user)
        {
            return user.FindFirstValue(ClaimTypes.Email);
        }
    }
}