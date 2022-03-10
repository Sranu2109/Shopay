using Core.Entities;
using Core.Specifications;

namespace Core.Interfaces
{
    public interface IGenericRepository<T> where T : BaseEntity
    {
        Task<T> GetByIdAsync(int id);        //get an entity by id method
        Task<IReadOnlyList<T>> ListAllAsync();   //read list of entities method
        Task<T> GetEntityWithSpec(ISpecification<T> spec);   //get an entity with a specification method
        Task<IReadOnlyList<T>> ListAsync(ISpecification<T> spec); //read entity with specification method
        Task<int> CountAsync(ISpecification<T> spec);    //coun the no. of items returned

        //additional methods to support updating
        void Add(T entity);   //no async becoz we'll not directly add this to db purpose is to just track this method
        void Update(T entity);  //generic repo is not responsible to save changes in db that is done by unit of work.
        void Delete(T entity);
        
  }
}