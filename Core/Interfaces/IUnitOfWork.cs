using Core.Entities;

namespace Core.Interfaces
{
    public interface IUnitOfWork : IDisposable    //disposal method gonna dispose our context after transaction
    {
        //entity framework will track all the changes to the entities (add, remove things to list)
        IGenericRepository<TEntity> Repository<TEntity>() where TEntity : BaseEntity;
        Task<int> Complete();  //returns no. of changes to our database
    }
}