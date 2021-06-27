using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace facebookIdentityKendiYaptigim.Identity
{
    public class User:IdentityUser
    {
        public string tc { get; set; }

    }
}
