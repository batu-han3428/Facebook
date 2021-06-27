using facebookIdentityKendiYaptigim.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace facebookIdentityKendiYaptigim.Extension
{
    public static class ServiceCollectionExtension
    {
        public static IServiceCollection IdentityServerAyarlari(this IServiceCollection services) {

            services.AddDbContext<Context>(opt => opt.UseSqlServer("Server=(localdb)\\MsSqlLocalDb;Database=KendiYaptigimFace;Trusted_Connection=true"));

            services.AddIdentity<User, IdentityRole>().AddEntityFrameworkStores<Context>().AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options => {

                options.Password.RequireDigit = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireLowercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 2;
                options.Password.RequireNonAlphanumeric = true;

                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);

                options.User.AllowedUserNameCharacters = "abcçdefgğhıijklmnoöpqrstuüvwxyzABCÇDEFGĞHIİJKLMNOÖPQRSTUÜVWXYZ0123456789-. _ @ +";
                options.User.RequireUniqueEmail = true;

                options.SignIn.RequireConfirmedEmail = true;
            });

            return services;
        }

        public static IServiceCollection CookieAyarlari(this IServiceCollection services)
        {
            services.ConfigureApplicationCookie(options => {

                options.LoginPath = "/Account/Login";
                options.LogoutPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.SlidingExpiration = true;
                options.Cookie.HttpOnly = true;
                options.Cookie.Name = "UyeCookie";
                options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict;
                options.ExpireTimeSpan = TimeSpan.FromMinutes(40);

            });

            return services;
        }
    }
}
