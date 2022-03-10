using System.Linq.Expressions;

namespace Core.Specifications
{
    public interface ISpecification<T>
    {
        Expression<Func<T, bool>> Criteria {get; }     //where clause
        List<Expression<Func<T, object>>> Includes {get; }
        Expression<Func<T, object>> OrderBy {get; } //generic expression of type T
        Expression<Func<T, object>> OrderByDescending {get; } 

        int Take {get; }  //property to take first few products
        int Skip {get; }  //property to skip some products
        bool IsPagingEnabled {get; }
    }
}