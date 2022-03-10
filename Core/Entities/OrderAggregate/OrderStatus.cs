using System.Runtime.Serialization;

namespace Core.Entities.OrderAggregate
{
    public enum OrderStatus   //to track status
    {
       // since we're using enum it will return default values so for text we'll add attribute
       [EnumMember(Value = "Pending")]
        Pending,

       // Shipped,

       [EnumMember(Value = "Payment Recieved")]
        PaymentRecieved,

        [EnumMember(Value = "Payment Failed")]
        PaymentFailed
        
    }
}