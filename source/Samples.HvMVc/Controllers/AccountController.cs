using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Web.Script.Serialization;
using System.Web.Security;
using Microsoft.Health;
using Microsoft.Health.Web;
using Microsoft.Health.Web.Authentication;
using Samples.HvMvc.Models;

namespace Samples.HvMvc.Controllers
{

    [Authorize]
    public class AccountController : Controller
    {

        //
        // GET: /Account/Login

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            if (HttpContext.Request.RawUrl.Contains("target=SignOut"))
                //when we sign out it will come to this page, so we just want to redirect to the login page
                return RedirectToAction("Index", "Home");
            else
            {
                //Redirect to health vault login which will post to the login method
                var url = Request.Params["ReturnUrl"] == null ? (Request.UrlReferrer.PathAndQuery == null ? "/" : Request.UrlReferrer.PathAndQuery) : Request.Params["ReturnUrl"];
                WebApplicationUtilities.RedirectToLogOn(System.Web.HttpContext.Current, true, url);
            }
            return View();
        }

        //
        // POST: /Account/Login

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Login(LoginModel model, string returnUrl)
        {
            // here we are getting posted from HealthVault so extract the wctoken sent
            string authToken = Request.Params["wctoken"];
            if (authToken != null)
            {
                // create a web app cred object
                var appId = HealthApplicationConfiguration.Current.ApplicationId;
                WebApplicationCredential cred =
                new WebApplicationCredential(
                    appId,
                    authToken,
                    HealthApplicationConfiguration.Current.ApplicationCertificate);

                // setup the user
                WebApplicationConnection connection = new WebApplicationConnection(appId, cred);
                PersonInfo personInfo = HealthVaultPlatform.GetPersonInfo(connection);

                // check to make sure there is access to records
                if (personInfo.AuthorizedRecords.Count() == 0)
                    throw new Exception("There are no authorized users for us to work with!");

                // check to see if the user exists
                var personId = personInfo.PersonId.ToString();

                // we found the user so authenticate them
                var username = personId;
                var password = personId + appId;
                if (Membership.ValidateUser(username, password))
                {
                    // user has authenticated
                    var user = Membership.GetUser(personInfo.PersonId.ToString());

                    // save auth cookie
                    CreateAuthCookie(personInfo, user);
                }
                else
                {
                    // the user has not registered with us so create one
                    // Attempt to register the user
                    MembershipCreateStatus createStatus;
                    var newUser = Membership.CreateUser(username, password, "", passwordQuestion: null, passwordAnswer: null, isApproved: true, providerUserKey: null, status: out createStatus);

                    if (createStatus == MembershipCreateStatus.Success)
                    {
                        //save auth cookie
                        CreateAuthCookie(personInfo, newUser);
                    }
                    else
                    {
                        ModelState.AddModelError("", ErrorCodeToString(createStatus));
                        return View(model);
                    }
                }

                // redirect to the actionqs
                NameValueCollection query = HttpUtility.ParseQueryString(Request.Url.Query);

                var r = HttpUtility.UrlDecode(query["actionqs"]);
                return Redirect(new Uri(string.Format("http://{0}{1}{2}",
                    Request.Url.Host,
                    (Request.Url.IsDefaultPort ? "" : ":" + Request.Url.Port), r)).ToString());
            }
            else
            {
                // no wctoken so just redirect to home
                ModelState.AddModelError("", "Unable to authenticate with Microsoft HealthVault.");
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }


        //
        // GET: /Account/LogOff

        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();

            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/Register

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register

        [AllowAnonymous]
        [HttpPost]
        public ActionResult Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // Attempt to register the user
                MembershipCreateStatus createStatus;
                Membership.CreateUser(model.UserName, model.Password, model.Email, passwordQuestion: null, passwordAnswer: null, isApproved: true, providerUserKey: null, status: out createStatus);

                if (createStatus == MembershipCreateStatus.Success)
                {
                    FormsAuthentication.SetAuthCookie(model.UserName, createPersistentCookie: false);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", ErrorCodeToString(createStatus));
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ChangePassword

        public ActionResult ChangePassword()
        {
            return View();
        }

        //
        // POST: /Account/ChangePassword

        [HttpPost]
        public ActionResult ChangePassword(ChangePasswordModel model)
        {
            if (ModelState.IsValid)
            {

                // ChangePassword will throw an exception rather
                // than return false in certain failure scenarios.
                bool changePasswordSucceeded;
                try
                {
                    MembershipUser currentUser = Membership.GetUser(User.Identity.Name, userIsOnline: true);
                    changePasswordSucceeded = currentUser.ChangePassword(model.OldPassword, model.NewPassword);
                }
                catch (Exception)
                {
                    changePasswordSucceeded = false;
                }

                if (changePasswordSucceeded)
                {
                    return RedirectToAction("ChangePasswordSuccess");
                }
                else
                {
                    ModelState.AddModelError("", "The current password is incorrect or the new password is invalid.");
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/ChangePasswordSuccess

        public ActionResult ChangePasswordSuccess()
        {
            return View();
        }

        private IEnumerable<string> GetErrorsFromModelState()
        {
            return ModelState.SelectMany(x => x.Value.Errors.Select(error => error.ErrorMessage));
        }

        #region Status Codes
        private static string ErrorCodeToString(MembershipCreateStatus createStatus)
        {
            // See http://go.microsoft.com/fwlink/?LinkID=177550 for
            // a full list of status codes.
            switch (createStatus)
            {
                case MembershipCreateStatus.DuplicateUserName:
                    return "User name already exists. Please enter a different user name.";

                case MembershipCreateStatus.DuplicateEmail:
                    return "A user name for that e-mail address already exists. Please enter a different e-mail address.";

                case MembershipCreateStatus.InvalidPassword:
                    return "The password provided is invalid. Please enter a valid password value.";

                case MembershipCreateStatus.InvalidEmail:
                    return "The e-mail address provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidAnswer:
                    return "The password retrieval answer provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidQuestion:
                    return "The password retrieval question provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.InvalidUserName:
                    return "The user name provided is invalid. Please check the value and try again.";

                case MembershipCreateStatus.ProviderError:
                    return "The authentication provider returned an error. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                case MembershipCreateStatus.UserRejected:
                    return "The user creation request has been canceled. Please verify your entry and try again. If the problem persists, please contact your system administrator.";

                default:
                    return "An unknown error occurred. Please verify your entry and try again. If the problem persists, please contact your system administrator.";
            }
        }
        #endregion

        private void CreateAuthCookie(PersonInfo personInfo, MembershipUser user)
        {
            // Create a new principal and serialize it
            var userData = new JavaScriptSerializer().Serialize(user);

            // create an auth ticket
            var authTicket = new FormsAuthenticationTicket(1,
                personInfo.PersonId.ToString(),
                DateTime.Now,
                DateTime.Now.AddHours(2),
                false,
                userData);

            // add the ticket to the cookies
            Response.Cookies.Add(new HttpCookie(FormsAuthentication.FormsCookieName, FormsAuthentication.Encrypt(authTicket)));
        }
    }
}
