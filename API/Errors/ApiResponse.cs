namespace API.Errors
{
    public class ApiResponse
    {
        public ApiResponse(int statusCode, string message = null)
        {
            StatusCode = statusCode;
            Message = message ?? GetDefaultMessageForStatusCode(statusCode);
        }

        public int StatusCode { get; set; }
        public string Message { get; set; }

        private string GetDefaultMessageForStatusCode(int statusCode)
        {
           return statusCode switch
           {
               400 => "You have made a Bad Request",
               401 => "You are not Authorized",
               404 => "No Resource was Found",
               500 => "Errors are the path to the dark sides. Errors lead to anger. Anger leads to hate. Hate leads to career change",
               _ => null
           };
        }
    }
}