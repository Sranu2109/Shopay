using System.ComponentModel.DataAnnotations;

namespace Core.Entities.OrderAggregate
{
    public class Address
    {
        public Address()  //parameter less constructor to avoid problems while adding migration 
        {
        }

        public Address(string firstName, string lastName, string street, string city, string state, string zipcode)   //parameterized constructor to initialize fields
        {
            FirstName = firstName;
            LastName = lastName;
            Street = street;
            City = city;
            State = state;
            Zipcode = zipcode;
        }
        //making properties of the fields
        public string FirstName { get; set; }    
        public string LastName { get; set; }
        public string Street { get; set; }
        public string City { get; set; }
        public string State { get; set; }

        [Required]
        public string Zipcode { get; set; }
        
    }
}