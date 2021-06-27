using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace facebookIdentityKendiYaptigim.Identity
{
    public class Context:IdentityDbContext<User>
    {
        public Context(DbContextOptions<Context> options):base(options)
        {

        }
    }
}
