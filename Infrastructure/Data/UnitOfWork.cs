using System.Collections;
using Core.Entities;
using Core.Interfaces;

namespace Infrastructure.Data
{
    public class UnitOfWork : IUnitOfWork     //unit of work stores storecontext
    {
        private readonly StoreContext _context;
        private Hashtable _repositories;        //any repositories that we use inside unit of work will be stored in hashtable
        public UnitOfWork(StoreContext context)
        {
            _context = context;
        }

        public async Task<int> Complete()
        {
            return await _context.SaveChangesAsync();
        }

        public void Dispose()
        {
            _context.Dispose();
        }

        public IGenericRepository<TEntity> Repository<TEntity>() where TEntity : BaseEntity
        {
            if(_repositories== null) _repositories = new Hashtable();   //check if hashtable already created because we created another instance of another repo

            var type = typeof(TEntity).Name;    //checks TEntity name

            if(!_repositories.ContainsKey(type))    //checks hashtable if it contains repo with its particular type
            {
                var repositoryType = typeof(GenericRepository<>);   //if not then create repo

                var repositoryInstance = Activator.CreateInstance(repositoryType.MakeGenericType(typeof(TEntity)), _context);     //creating instance of the repo of product and pass context we get from unit of work

                _repositories.Add(type, repositoryInstance);   //adding repo in hashtable
            }

            return (IGenericRepository<TEntity>) _repositories[type];      //then return it
        }
    }
}