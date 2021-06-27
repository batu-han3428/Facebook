using facebookIdentityKendiYaptigim.Identity;
using facebookIdentityKendiYaptigim.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace facebookIdentityKendiYaptigim.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<User> userManager;
        private readonly SignInManager<User> signInManager;
        public AccountController(UserManager<User> userManager, SignInManager<User> signInManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public IActionResult Login()
        {
            return View(new LoginModel());
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            if (!ModelState.IsValid)
            {

                return View(loginModel);
            }
            else
            {
                var user = await userManager.FindByEmailAsync(loginModel.Email);

                if (user == null)
                {
                    ModelState.AddModelError("", "Bu mail kayitli degildir");
                    return View(loginModel);
                }

                if (!await userManager.IsEmailConfirmedAsync(user))
                {
                    ModelState.AddModelError("", "Bu mail onaylanmamistir. Lutfen mail box'inizi kontrol ediniz");
                    return View(loginModel);
                }

                var result = await signInManager.PasswordSignInAsync(user, loginModel.Password, loginModel.RememberMe, true);

                if (result.Succeeded)
                {
                    return RedirectToAction("Privacy", "Home");
                }

                ModelState.AddModelError("", "Email yada parola yanliş"); 
                return View(loginModel);
            }
        }

        public async Task<IActionResult> Logout()
        {
            await signInManager.SignOutAsync();

            return Redirect("~/");
        }

        public IActionResult Register()
        {

            return View(new RegisterModel());
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterModel registerModel)
        {
            if (!ModelState.IsValid)
            {

                return View(registerModel);
            }
            else
            {
                var user = new User
                {
                    UserName = registerModel.UserName,
                    Email = registerModel.Email,
                    tc = registerModel.Tckimlik
                };

                var result = await userManager.CreateAsync(user, registerModel.Password);

                if (result.Succeeded)
                {
                    var code = await userManager.GenerateEmailConfirmationTokenAsync(user);

                    return RedirectToAction("Login", "Account");
                }

                ModelState.AddModelError("", "Şifreniz yada email adresiniz dogru girilmemiş . Kontrol Ediniz. UsernName de hatali olabilir . Onda bak.");
                return View(registerModel);
            }

        }

        public IActionResult FacebookLogin(string ReturnUrl)
        {
            string redirectUrl = Url.Action("FacebookResponse", "Account", new { ReturnUrl = ReturnUrl });
            //Facebook'a yapılan Login talebi neticesinde kullanıcıyı yönlendirmesini istediğimiz url'i oluşturuyoruz.
            
            AuthenticationProperties properties = signInManager.ConfigureExternalAuthenticationProperties("Facebook", redirectUrl);
            //Bağlantı kurulacak harici platformun hangisi olduğunu belirtiyor ve bağlantı özelliklerini elde ediyoruz.
            
            return new ChallengeResult("Facebook", properties);
            //ChallengeResult; kimlik doğrulamak için gerekli olan tüm özellikleri kapsayan AuthenticationProperties nesnesini alır ve ayarlar.
        }

        public async Task<IActionResult> FacebookResponse(string ReturnUrl = "/")
        {
            ExternalLoginInfo loginInfo = await signInManager.GetExternalLoginInfoAsync();
            //Kullanıcıyla ilgili Facebook'tan gelen tüm bilgileri taşıyan nesnedir.
            //Bu nesnesnin 'LoginProvider' propertysinin değerine göz atarsanız eğer Facebook yazdığını göreceksiniz.
            //Eğer ki, Login işlemi Google yahut Twitter üzerinde gerçekleştirilmiş olsaydı provider olarak ilgili platformun adı yazacaktı.
            if (loginInfo == null)
                return RedirectToAction("Login");
            else
            {
                Microsoft.AspNetCore.Identity.SignInResult loginResult = await signInManager.ExternalLoginSignInAsync(loginInfo.LoginProvider, loginInfo.ProviderKey, true);
                //Giriş yapıyoruz.
                if (loginResult.Succeeded)
                    return Redirect(ReturnUrl);
                else
                {
                    //Eğer ki akış bu bloğa girerse ilgili kullanıcı uygulamamıza kayıt olmadığından dolayı girişi başarısız demektir.
                    //O halde kayıt işlemini yapıp, ardından giriş yaptırmamız gerekmektedir.
                    User user = new User
                    {
                        Email = loginInfo.Principal.FindFirst(ClaimTypes.Email).Value,
                        UserName = loginInfo.Principal.FindFirst(ClaimTypes.Email).Value
                    };
                    //Facebook'tan gelen Claimleri uygun eşlendikleri propertylere atıyoruz.
                    IdentityResult createResult = await userManager.CreateAsync(user);
                    //Kullanıcı kaydını yapıyoruz.
                    if (createResult.Succeeded)
                    {
                        //Eğer kayıt başarılıysa ilgili kullanıcı bilgilerini AspNetUserLogins tablosuna kaydetmemiz gerekmektedir ki
                        //bir sonraki Facebook login talebinde Identity mimarisi ilgili kullanıcının Facebook'tan geldiğini anlayabilsin.
                        IdentityResult addLoginResult = await userManager.AddLoginAsync(user, loginInfo);
                        //Kullanıcı bilgileri Facebook'tan gelen bilgileriyle AspNetUserLogins tablosunda eşleştirilmek suretiyle kaydedilmiştir.
                        if (addLoginResult.Succeeded)
                        {
                            await signInManager.SignInAsync(user, true);
                            return Redirect(ReturnUrl);
                        }
                    }

                }
            }
            return Redirect(ReturnUrl);
        }
    }
}
