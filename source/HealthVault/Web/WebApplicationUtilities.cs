// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.Web;
using System.Web.Configuration;
using Microsoft.Health;
using Microsoft.Health.Web.Authentication;
using System.Diagnostics;
using System.Collections.Specialized;
using System.Globalization;
using System.Security.Cryptography;

namespace Microsoft.Health.Web
{
    /// <summary> 
    /// A collection of utility functions to help HealthVault web application developers 
    /// authenticate and perform other actions with HealthVault.
    /// </summary>
    /// 
    /// <remarks>
    /// If possible, it is recommended that HealthVault applications derive from
    /// <see cref="HealthServicePage"/>. If the requirements for the application don't allow for
    /// derivation due to deriving from another base class or needing access from control classes,
    /// the static utility methods in this class give the developer access to the same functionality
    /// that is available in the <see cref="HealthServicePage"/>.
    /// <br/><br/>
    /// Methods like <see cref="PageOnInit"/> and 
    /// <see cref="PageOnPreLoad(HttpContext, bool, bool)"/> should be called from
    /// the application's page <see cref="System.Web.UI.Page.OnInit"/> and 
    /// <see cref="System.Web.UI.Page.OnPreLoad"/> methods respectively.
    /// <br/><br/>
    /// Other methods help the application with management of the HealthVault cookie. For instance,
    /// <see cref="LoadPersonInfoFromCookie(HttpContext)"/> reads the HealthVault cookie from the request and
    /// instantiates the <see cref="PersonInfo"/> instance for the logged in person. Note, some
    /// methods like <see cref="LoadPersonInfoFromCookie(HttpContext)"/> require another method be called first
    /// to handle the user's authentication token. Methods like 
    /// <see cref="SavePersonInfoToCookie(HttpContext, PersonInfo)"/> and 
    /// <see cref="RefreshAndSavePersonInfoToCookie(HttpContext, PersonInfo)"/> deal with storing the HealthVault user information in a 
    /// cookie or session.
    /// </remarks>
    /// 
    public static class WebApplicationUtilities
    {
        internal const string QueryStringToken = "WCToken";
        internal const string PersistentTokenTtl = "suggestedtokenttl";

        internal const string WcTokenExpiration = "e";
        internal const string WcTokenPersonInfo = "p";

        static int CookieMaxSize = 2048;

        #region OnInit
        /// <summary>
        /// Replicates the <see cref="HealthServicePage.OnInit"/> behavior by redirecting to a 
        /// secure version of the page if the URL requested is insecure and the application requires
        /// a secure connection.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="isPageSslSecure">
        /// If true, the application requires all connections to this page be over a secure SSL
        /// channel.
        /// </param>
        /// 
        /// <remarks>
        /// Applications can require certain pages (or all pages) to be accessed only over a secure
        /// SSL channel. To do this the application must set the "WCPage_SSLForSecure" config value
        /// in the web.config file and pass "true" to <paramref name="isPageSslSecure"/>.
        /// <br/><br/>
        /// If the conditions above are true the user's browser will automatically be redirected
        /// to a secure version of the page.
        /// </remarks>
        /// 
        public static void PageOnInit(HttpContext context, bool isPageSslSecure)
        {
            if (isPageSslSecure)
            {
                string redirectUrl = GetSSLRedirectURL(context.Request);
                if (redirectUrl != null)
                {
                    context.Response.Redirect(redirectUrl);
                }
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        /// 
        /// <remarks>
        /// This is usually called during page initialization (<see cref="System.Web.UI.Page.OnInit"/>).
        /// If a <see cref="System.Uri"/> is returned then the user should be redirected to the
        /// specified URL.
        /// </remarks>
        /// 
        private static string GetSSLRedirectURL(HttpRequest request)
        {
            string result = null;
            if (HealthWebApplicationConfiguration.Current.UseSslForSecurity)
            {
                if (!request.IsSecureConnection)
                {
                    //RedirectToSecure
                    StringBuilder secureUrl = new StringBuilder();
                    secureUrl.Append(
                        HealthWebApplicationConfiguration.Current.SecureHttpScheme);
                    secureUrl.Append(request.Url.Host);
                    secureUrl.Append(request.Url.PathAndQuery);
                    result = secureUrl.ToString();
                }
            }
            else
            {
                if (request.IsSecureConnection)
                {
                    //RedirectToInsecure
                    StringBuilder inSecureUrl = new StringBuilder();
                    inSecureUrl.Append(
                        HealthWebApplicationConfiguration.Current.InsecureHttpScheme);
                    inSecureUrl.Append(request.Url.Host);
                    inSecureUrl.Append(request.Url.PathAndQuery);
                    result = inSecureUrl.ToString();
                }
            }
            return result;
        }
        #endregion OnInit

        #region OnPreLoad

        /// <summary>
        /// Ensures that the person is logged on if <paramref name="logOnRequired"/> is true.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="logOnRequired">
        /// True if the requested page requires the user to be logged on to HealthVault, or false
        /// otherwise. If true and the user isn't logged on, the user's browser will be automatically
        /// redirected to the HealthVault authentication page.
        /// </param>
        /// 
        /// <remarks>
        /// It is recommended that HealthVault applications that cannot derive from 
        /// <see cref="HealthServicePage"/> call this method during their pages OnPreLoad. This
        /// method will ensure that the HealthVault token is extracted from the URL query string,
        /// the authenticated person's <see cref="PersonInfo"/> is retrieved and stored in a cookie.
        /// This will make the person's information available through the cookie on all future 
        /// requests until they log off.
        /// </remarks>
        /// 
        public static PersonInfo PageOnPreLoad(HttpContext context, bool logOnRequired)
        {
            return PageOnPreLoad(
                context, 
                logOnRequired, 
                false,
                HealthWebApplicationConfiguration.Current.ApplicationId);
        }


        /// <summary>
        /// Ensures that the person is logged on if <paramref name="logOnRequired"/> is true.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="logOnRequired">
        /// True if the requested page requires the user to be logged on to HealthVault, or false
        /// otherwise. If true and the user isn't logged on, the user's browser will be automatically
        /// redirected to the HealthVault authentication page.
        /// </param>
        /// 
        /// <param name="appId">
        /// The unique application identifier.
        /// </param>
        /// 
        /// <remarks>
        /// It is recommended that HealthVault applications that cannot derive from 
        /// <see cref="HealthServicePage"/> call this method during their pages OnPreLoad. This
        /// method will ensure that the HealthVault token is extracted from the URL query string,
        /// the authenticated person's <see cref="PersonInfo"/> is retrieved and stored in a cookie.
        /// This will make the person's information available through the cookie on all future 
        /// requests until they log off.
        /// </remarks>
        /// 
        public static PersonInfo PageOnPreLoad(HttpContext context, bool logOnRequired, Guid appId)
        {
            return PageOnPreLoad(context, logOnRequired, false /* isMra */, appId);
        }

        /// <summary>
        /// Ensures that the person is logged on if <paramref name="logOnRequired"/> is true.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="logOnRequired">
        /// True if the requested page requires the user to be logged on to HealthVault, or false
        /// otherwise. If true and the user isn't logged on, the user's browser will be automatically
        /// redirected to the HealthVault authentication page.
        /// </param>
        /// 
        /// <param name="isMra">
        /// Whether this application simultaneously deals with multiple records
        /// for the same person.
        /// </param>
        /// 
        /// <remarks>
        /// It is recommended that HealthVault applications that cannot derive from 
        /// <see cref="HealthServicePage"/> call this method during their pages OnPreLoad. This
        /// method will ensure that the HealthVault token is extracted from the URL query string,
        /// the authenticated person's <see cref="PersonInfo"/> is retrieved and stored in a cookie.
        /// This will make the person's information available through the cookie on all future 
        /// requests until they log off.
        /// </remarks>
        /// 
        public static PersonInfo PageOnPreLoad(HttpContext context, bool logOnRequired, bool isMra)
        {
            return PageOnPreLoad(
                context, 
                logOnRequired, 
                isMra,
                HealthWebApplicationConfiguration.Current.ApplicationId);
        }


        /// <summary>
        /// Ensures that the person is logged on if <paramref name="logOnRequired"/> is true.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="logOnRequired">
        /// True if the requested page requires the user to be logged on to HealthVault, or false
        /// otherwise. If true and the user isn't logged on, the user's browser will be automatically
        /// redirected to the HealthVault authentication page.
        /// </param>
        /// 
        /// <param name="isMra">
        /// Whether this application simultaneously deals with multiple records
        /// for the same person.
        /// </param>
        /// 
        /// <param name="appId">
        /// The unique identifier for the application.
        /// </param>
        /// 
        /// <remarks>
        /// It is recommended that HealthVault applications that cannot derive from 
        /// <see cref="HealthServicePage"/> call this method during their pages OnPreLoad. This
        /// method will ensure that the HealthVault token is extracted from the URL query string,
        /// the authenticated person's <see cref="PersonInfo"/> is retrieved and stored in a cookie.
        /// This will make the person's information available through the cookie on all future 
        /// requests until they log off.
        /// </remarks>
        /// 
        public static PersonInfo PageOnPreLoad(
            HttpContext context,
            bool logOnRequired,
            bool isMra,
            Guid appId)
        {
            // this will redirect if needed 
            // NOTE: I reverted this code because it was spreading query
            // string info around as it was previously.
            HandleTokenOnUrl(context, logOnRequired, appId);

            // Get whatever's in the cookie...
            PersonInfo personInfo = LoadPersonInfoFromCookie(context);

            // If we didn't just authenticate and the cookie was blank and
            // we ought to be logged in...
            if (logOnRequired && personInfo == null)
            {
                // If we need a signup code for account creation, get it now
                // and pass it to HealthVault.
                string signupCode = null;
                if (HealthWebApplicationConfiguration.Current.IsSignupCodeRequired)
                {
                    signupCode = HealthVaultPlatform.NewSignupCode(ApplicationConnection);
                }

                RedirectToLogOn(context, isMra, context.Request.Url.PathAndQuery, signupCode);
            }

            SavePersonInfoToCookie(context, personInfo, false);
            return personInfo;
        }

        #endregion OnPreLoad

        /// <summary>
        /// Gets a credential used to authenticate the web application to
        /// HealthVault.
        /// </summary>
        public static WebApplicationCredential ApplicationAuthenticationCredential
        {
            get
            {
                return GetApplicationAuthenticationCredential(
                    HealthWebApplicationConfiguration.Current.ApplicationId);
            }
        }

        /// <summary>
        /// Gets a credential used to authenticate the web application to
        /// Microsoft HealthVault.
        /// </summary>
        /// 
        /// <param name="appId">
        /// The unique application identifier to get the credential for.
        /// </param>
        /// 
        /// <returns>
        /// The application credential for the specified application.
        /// </returns>
        /// 
        public static WebApplicationCredential GetApplicationAuthenticationCredential(Guid appId)
        {
            return 
                new WebApplicationCredential(
                    appId, 
                    HealthApplicationConfiguration.Current.ApplicationCertificate);
        }

        /// <summary>
        /// Gets a HealthVault application connection without a user context.
        /// </summary>
        /// 
        /// <returns>
        /// A <see cref="Microsoft.Health.ApplicationConnection"/> connection.
        /// </returns>
        /// 
        /// <remarks>
        /// If a connection has already been made on the page, that connection
        /// is returned. If no connection has been made, a new connection is
        /// created and returned.
        /// </remarks>
        /// 
        /// <exception cref="System.Security.SecurityException">
        /// If the application private key could not be found in the 
        /// certificate store to sign requests.
        /// </exception>
        /// 
        public static ApplicationConnection ApplicationConnection
        {
            get
            {
                return GetApplicationConnection(
                    HealthWebApplicationConfiguration.Current.ApplicationId);
            }
        }


        /// <summary>
        /// Gets a HealthVault application connection without a user context.
        /// </summary>
        /// 
        /// <param name="appId">
        /// The unique application identifier for the application to get the connection for.
        /// </param>
        /// 
        /// <returns>
        /// A <see cref="Microsoft.Health.ApplicationConnection"/> connection.
        /// </returns>
        /// 
        /// <remarks>
        /// If a connection has already been made on the page, that connection
        /// is returned. If no connection has been made, a new connection is
        /// created and returned.
        /// </remarks>
        /// 
        /// <exception cref="System.Security.SecurityException">
        /// If the application private key could not be found in the 
        /// certificate store to sign requests.
        /// </exception>
        /// 
        public static ApplicationConnection GetApplicationConnection(Guid appId)
        {
            return new OfflineWebApplicationConnection(
                GetApplicationAuthenticationCredential(appId),
                Guid.Empty);
        }

        /// <summary>
        /// Gets a HealthVault connection for the authenticated user.
        /// </summary>
        /// 
        /// <returns>
        /// A <see cref="WebApplicationConnection"/>.
        /// </returns>
        /// 
        /// <remarks>
        /// If a connection has already been made on the page, that connection
        /// is returned. If no connection has been made, a new connection is
        /// created and returned.
        /// </remarks>
        /// 
        /// <exception cref="System.Security.SecurityException">
        /// If the application private key could not be found in the 
        /// certificate store to sign requests.
        /// </exception>
        /// 
        /// <exception cref="InvalidOperationException">
        /// If a person has not been logged in.
        /// </exception>
        /// 
        public static WebApplicationConnection GetAuthenticatedConnection(HttpContext context)
        {
            PersonInfo personInfo = LoadPersonInfoFromCookie(context);

            Validator.ThrowInvalidIfNull(personInfo, "PersonNotLoggedIn");

            return
                new WebApplicationConnection(
                    ((AuthenticatedConnection)personInfo.ApplicationConnection).Credential);
        }

        /// <summary>
        /// Gets a HealthVault connection without an authentication token for the user but with
        /// an application authentication token.
        /// </summary>
        /// 
        /// <returns>
        /// A <see cref="ApplicationConnection"/> connection.
        /// </returns>
        /// 
        /// <remarks>
        /// If a connection has already been made on the page, that connection
        /// is returned. If no connection has been made, a new connection is
        /// created a returned.
        /// </remarks>
        /// 
        /// <exception cref="System.Security.SecurityException">
        /// If the application private key could not be found in the 
        /// certificate store to sign requests.
        /// </exception>
        /// 
        public static ApplicationConnection DictionaryConnection
        {
            get
            {
                return ApplicationConnection;
            }
        }

        /// <summary>
        /// Gets a HealthVault connection without an authentication token for either the user or
        /// the application.
        /// </summary>
        /// 
        /// <returns>
        /// A connection to HealthVault that does not contain user or application
        /// authentication information.
        /// </returns>
        /// 
        /// <remarks>
        /// If a connection has already been made on the page, that connection
        /// is returned. If no connection has been made, a new connection is
        /// created a returned.
        /// </remarks>
        /// 
        /// <exception cref="System.Security.SecurityException">
        /// If the application private key could not be found in the 
        /// certificate store to sign requests.
        /// </exception>
        /// 
        public static AnonymousConnection AnonymousConnection
        {
            get
            {
                return new AnonymousConnection();
            }
        }

        /// <summary> 
        /// Cleans the application's session of HealthVault information and 
        /// then repopulates it.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="personInfo">
        /// The information about the authenticated person that needs refreshing.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// If a person isn't logged on when this is called.
        /// </exception>
        /// 
        /// <remarks>
        /// This method should be called anytime an action occurs that will affect the 
        /// <see cref="PersonInfo"/> object for the authenticated person. This includes changing
        /// the person's authorization for the application or changing the selected record.
        /// </remarks>
        /// 
        public static PersonInfo RefreshAndSavePersonInfoToCookie(
            HttpContext context, 
            PersonInfo personInfo)
        {
            Validator.ThrowInvalidIfNull(personInfo, "PersonNotLoggedIn");

            personInfo = HealthVaultPlatform.GetPersonInfo(personInfo.ApplicationConnection);

            SavePersonInfoToCookie(context, personInfo);
            return personInfo;
        }

        internal static void OnPersonInfoChanged(Object sender, EventArgs e)
        {
            PersonInfo personInfo = sender as PersonInfo;

            if (personInfo != null)
            {
                SavePersonInfoToCookie(HttpContext.Current, personInfo);
            }
        }

        /// <summary>
        /// Stores the specified person's information in the cookie.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="personInfo">
        /// The authenticated person's information.
        /// </param>
        /// 
        /// <remarks>
        /// If <paramref name="personInfo"/> is null, this call will not clear the cookie.
        /// </remarks>
        /// 
        public static void SavePersonInfoToCookie(HttpContext context, PersonInfo personInfo)
        {
            SavePersonInfoToCookie(context, personInfo, false);
        }

        /// <summary> 
        /// Cleans the application's session of HealthVault information and 
        /// then repopulates it using the specified authentication token.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="authToken">
        /// The authentication to use to populate the session with HealthVault
        /// information.
        /// </param>
        /// 
        /// <exception cref="HealthServiceException">
        /// If HealthVault returns an error when getting information
        /// about the person in the <paramref name="authToken"/>.
        /// </exception>
        /// 
        /// <remarks>
        /// This method should be called anytime the application takes a redirect from the 
        /// HealthVault shell and there is a WCToken on the query string. Note, if you are calling
        /// <see cref="PageOnPreLoad(HttpContext, bool, bool)"/> or 
        /// <see cref="PageOnPreLoad(HttpContext, bool)"/> this is handled for you.
        /// </remarks>
        /// 
        public static PersonInfo RefreshAndSavePersonInfoToCookie(
            HttpContext context, 
            string authToken)
        {
            PersonInfo personInfo = GetPersonInfo(authToken);
            SavePersonInfoToCookie(context, personInfo);
            return personInfo;
        }

        /// <summary>
        /// Redirects to the HealthVault Shell URL with the queryString params 
        /// appended.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="targetLocation">
        /// A known constant indicating the internal HealthVault 
        /// service Shell location to redirect to.
        /// 
        /// Locations and their parameters include:
        /// <ul>
        ///     <li><b>APPAUTH</b> - allows the user to select and authorize a health record for use 
        ///             with the specified application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPCONTENT</b> - display application specific content such as privacy  
        ///             statement or terms of use.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>target - used to specify content to display.  The same supported values 
        ///                 as <see cref="HealthServiceActionPage.Action"/> property.
        ///             </li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPREDIRECT</b> - Redirect user to a HealthVault application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the destination application.</li>
        ///             <li>refappid - A GUID that uniquely identifies the referring application.</li>
        ///             <li>target - string used as the "target" parameter when user browser is 
        ///                      redirected to the destination application's action-url.</li>
        ///             <li>targetqs - string used as the "targetqs" parameter when user browser is 
        ///                      redirected to the destination application's action-url</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPSIGNOUT</b> - Signs the user out of HealthVault.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>AUTH</b> - the sign-in page
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at one time.</li>
        ///             <li>forceappauth - force redirect to APPAUTH target once user is authenticated.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEACCOUNT</b> - Allows the user to create a new HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>nsi - no sign in page. The sign in page (where the user enters an email address) is bypassed if set to 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEAPPLICATION</b> - Allows a SODA master application to create a new client application instance.
        ///         <ul>
        ///             <li>publickey - the public key of the new client application instance.  The key
        ///                      must be an X509 certificate that is base64 encoded.</li>
        ///             <li>appid - the GUID that uniquely identifies the SODA master application.  The new application instance will
        ///                      be a child of this master application.</li>
        ///             <li>instanceid - the GUID that will be assigned to the client application.  This ID must be unique
        ///                      for every application instance.</li>
        ///             <li>instancename - A string that identifies the device the new application instance will run on, such
        ///                      as the computer name.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATERECORD</b> - Allows the user to create a new HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>HELP</b> - The HealthVault help page.
        ///         <ul>
        ///             <li>topicid - optional. If not specified the table of contents will be shown.
        ///                 <ul>
        ///                     <li>faq - HealthVault Frequently Asked Questions</li>
        ///                     <li>HelpDirectory - Main HealthVault help page</li>
        ///                     <li>PrivacyPolicy - HealthVault privacy policy</li>
        ///                     <li>Service Agreement - HealthVault Service Agreement</li>
        ///                     <li>CodeofConduct - HealthVault Code of Conduct</li>
        ///                 </ul>
        ///             </li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>MANAGEACCOUNT</b> - Takes the user to a page to manage their account profile.
        ///     <br />The shell does not provide a mechanism to return to the application from the
        ///     account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>RECONCILE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item and transform/merge them into individual HealthVault items in their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>RECORDLIST</b> - A page that lists all records of a HealthVault user.
        ///         <ul>
        ///             <li>appid - optional, the page displays only records which the specified application is authorized to access.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>SHAREDAPPDETAILS</b> - Allows the user to manage application authorization for a HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>SHARERECORD</b> - Allows the user to share a record that they are a custodian of to another HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>VIEWITEMS</b> - Allows a HealthVault user to view all of the items of the specified data type in the their record.
        ///         <ul>
        ///             <li>typeid - data type identifier.</li>
        ///             <li>additem - flag to show the new item dialog for the data type.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        /// </ul>
        /// </param>
        /// 
        /// <param name="targetQuery">
        /// The query string value to pass to the URL to which redirection is 
        /// taking place. 
        /// </param>
        /// 
        /// <remarks>
        /// The <paramref name="targetLocation"/> will be passed as the target parameter value to
        /// the redirector URL.
        /// The <paramref name="targetQuery"/> will be URL encoded and passed as the targetqs 
        /// parameter value to the redirector URL.
        /// </remarks>
        /// 
        public static void RedirectToShellUrl(
            HttpContext context,
            string targetLocation,
            string targetQuery)
        {
            context.Response.Redirect(
                ConstructShellTargetUrl(
                    context,
                    targetLocation, 
                    targetQuery).OriginalString);
        }

        /// <summary>
        /// Redirects to the HealthVault Shell URL with the queryString params 
        /// appended.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="targetLocation">
        /// A known constant indicating the internal HealthVault 
        /// service Shell location to redirect to.
        /// 
        /// Locations and their parameters include:
        /// <ul>
        ///     <li><b>APPAUTH</b> - allows the user to select and authorize a health record for use 
        ///             with the specified application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPCONTENT</b> - display application specific content such as privacy  
        ///             statement or terms of use.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>target - used to specify content to display.  The same supported values 
        ///                 as <see cref="HealthServiceActionPage.Action"/> property.
        ///             </li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPREDIRECT</b> - Redirect user to a HealthVault application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the destination application.</li>
        ///             <li>refappid - A GUID that uniquely identifies the referring application.</li>
        ///             <li>target - string used as the "target" parameter when user browser is 
        ///                      redirected to the destination application's action-url.</li>
        ///             <li>targetqs - string used as the "targetqs" parameter when user browser is 
        ///                      redirected to the destination application's action-url</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPSIGNOUT</b> - Signs the user out of HealthVault.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>AUTH</b> - the sign-in page
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at one time.</li>
        ///             <li>forceappauth - force redirect to APPAUTH target once user is authenticated.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEACCOUNT</b> - Allows the user to create a new HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>nsi - no sign in page. The sign in page (where the user enters an email address) is bypassed if set to 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEAPPLICATION</b> - Allows a SODA master application to create a new client application instance.
        ///         <ul>
        ///             <li>publickey - the public key of the new client application instance.  The key
        ///                      must be an X509 certificate that is base64 encoded.</li>
        ///             <li>appid - the GUID that uniquely identifies the SODA master application.  The new application instance will
        ///                      be a child of this master application.</li>
        ///             <li>instanceid - the GUID that will be assigned to the client application.  This ID must be unique
        ///                      for every application instance.</li>
        ///             <li>instancename - A string that identifies the device the new application instance will run on, such
        ///                      as the computer name.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATERECORD</b> - Allows the user to create a new HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>HELP</b> - The HealthVault help page.
        ///         <ul>
        ///             <li>topicid - optional. If not specified the table of contents will be shown.
        ///                 <ul>
        ///                     <li>faq - HealthVault Frequently Asked Questions</li>
        ///                     <li>HelpDirectory - Main HealthVault help page</li>
        ///                     <li>PrivacyPolicy - HealthVault privacy policy</li>
        ///                     <li>Service Agreement - HealthVault Service Agreement</li>
        ///                     <li>CodeofConduct - HealthVault Code of Conduct</li>
        ///                 </ul>
        ///             </li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>MANAGEACCOUNT</b> - Takes the user to a page to manage their account profile.
        ///     <br />The shell does not provide a mechanism to return to the application from the
        ///     account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>RECONCILE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item and transform/merge them into individual HealthVault items in their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>RECORDLIST</b> - A page that lists all records of a HealthVault user.
        ///         <ul>
        ///             <li>appid - optional, the page displays only records which the specified application is authorized to access.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>SHAREDAPPDETAILS</b> - Allows the user to manage application authorization for a HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>SHARERECORD</b> - Allows the user to share a record that they are a custodian of to another HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>VIEWITEMS</b> - Allows a HealthVault user to view all of the items of the specified data type in the their record.
        ///         <ul>
        ///             <li>typeid - data type identifier.</li>
        ///             <li>additem - flag to show the new item dialog for the data type.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        /// </ul>
        /// </param>
        /// 
        /// <param name="targetQuery">
        /// The query string value to pass to the URL to which redirection is 
        /// taking place. 
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters passed to the calling application action URL after the
        /// target action is completed in the Shell.
        /// </param>
        /// 
        /// <remarks>
        /// The <paramref name="targetLocation"/> will be passed as the target parameter value to
        /// the redirector URL.
        /// The <paramref name="targetQuery"/> will be URL encoded and passed as the targetqs 
        /// parameter value to the redirector URL.
        /// The <paramref name="actionUrlQueryString"/> will be URL encoded and passed as the actionqs
        /// parameter value to the redirector URL.
        /// </remarks>
        /// 
        public static void RedirectToShellUrl(
            HttpContext context,
            string targetLocation,
            string targetQuery,
            string actionUrlQueryString)
        {
            context.Response.Redirect(
                ConstructShellTargetUrl(
                    context,
                    targetLocation, 
                    targetQuery, 
                    actionUrlQueryString).OriginalString);
        }

        /// <summary>
        /// Redirects to the HealthVault Shell URL with the query string params 
        /// appended.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="targetLocation">
        /// A known constant indicating the internal HealthVault 
        /// service Shell location to redirect to.
        /// 
        /// Locations and their parameters include:
        /// <ul>
        ///     <li><b>APPAUTH</b> - allows the user to select and authorize a health record for use 
        ///             with the specified application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPCONTENT</b> - display application specific content such as privacy  
        ///             statement or terms of use.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>target - used to specify content to display.  The same supported values 
        ///                 as <see cref="HealthServiceActionPage.Action"/> property.
        ///             </li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPREDIRECT</b> - Redirect user to a HealthVault application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the destination application.</li>
        ///             <li>refappid - A GUID that uniquely identifies the referring application.</li>
        ///             <li>target - string used as the "target" parameter when user browser is 
        ///                      redirected to the destination application's action-url.</li>
        ///             <li>targetqs - string used as the "targetqs" parameter when user browser is 
        ///                      redirected to the destination application's action-url</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPSIGNOUT</b> - Signs the user out of HealthVault.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>AUTH</b> - the sign-in page
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at one time.</li>
        ///             <li>forceappauth - force redirect to APPAUTH target once user is authenticated.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEACCOUNT</b> - Allows the user to create a new HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>nsi - no sign in page. The sign in page (where the user enters an email address) is bypassed if set to 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEAPPLICATION</b> - Allows a SODA master application to create a new client application instance.
        ///         <ul>
        ///             <li>publickey - the public key of the new client application instance.  The key
        ///                      must be an X509 certificate that is base64 encoded.</li>
        ///             <li>appid - the GUID that uniquely identifies the SODA master application.  The new application instance will
        ///                      be a child of this master application.</li>
        ///             <li>instanceid - the GUID that will be assigned to the client application.  This ID must be unique
        ///                      for every application instance.</li>
        ///             <li>instancename - A string that identifies the device the new application instance will run on, such
        ///                      as the computer name.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATERECORD</b> - Allows the user to create a new HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>HELP</b> - The HealthVault help page.
        ///         <ul>
        ///             <li>topicid - optional. If not specified the table of contents will be shown.
        ///                 <ul>
        ///                     <li>faq - HealthVault Frequently Asked Questions</li>
        ///                     <li>HelpDirectory - Main HealthVault help page</li>
        ///                     <li>PrivacyPolicy - HealthVault privacy policy</li>
        ///                     <li>Service Agreement - HealthVault Service Agreement</li>
        ///                     <li>CodeofConduct - HealthVault Code of Conduct</li>
        ///                 </ul>
        ///             </li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>MANAGEACCOUNT</b> - Takes the user to a page to manage their account profile.
        ///     <br />The shell does not provide a mechanism to return to the application from the
        ///     account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>RECONCILE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item and transform/merge them into individual HealthVault items in their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>RECORDLIST</b> - A page that lists all records of a HealthVault user.
        ///         <ul>
        ///             <li>appid - optional, the page displays only records which the specified application is authorized to access.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>SHAREDAPPDETAILS</b> - Allows the user to manage application authorization for a HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>SHARERECORD</b> - Allows the user to share a record that they are a custodian of to another HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>VIEWITEMS</b> - Allows a HealthVault user to view all of the items of the specified data type in the their record.
        ///         <ul>
        ///             <li>typeid - data type identifier.</li>
        ///             <li>additem - flag to show the new item dialog for the data type.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        /// </ul>
        /// </param>
        /// 
        /// <remarks>
        /// The <paramref name="targetLocation"/> will be passed as the target parameter value to
        /// the redirector URL.
        /// </remarks>
        /// 
        public static void RedirectToShellUrl(HttpContext context, string targetLocation)
        {
            context.Response.Redirect(
                ConstructShellTargetUrl(
                    context,
                    targetLocation).OriginalString);
        }


        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault URL 
        /// redirector.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="targetLocation">
        /// A known constant indicating the internal HealthVault 
        /// service Shell location to redirect to.
        /// 
        /// Locations and their parameters include:
        /// <ul>
        ///     <li><b>APPAUTH</b> - allows the user to select and authorize a health record for use 
        ///             with the specified application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPCONTENT</b> - display application specific content such as privacy  
        ///             statement or terms of use.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>target - used to specify content to display.  The same supported values 
        ///                 as <see cref="HealthServiceActionPage.Action"/> property.
        ///             </li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPREDIRECT</b> - Redirect user to a HealthVault application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the destination application.</li>
        ///             <li>refappid - A GUID that uniquely identifies the referring application.</li>
        ///             <li>target - string used as the "target" parameter when user browser is 
        ///                      redirected to the destination application's action-url.</li>
        ///             <li>targetqs - string used as the "targetqs" parameter when user browser is 
        ///                      redirected to the destination application's action-url</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPSIGNOUT</b> - Signs the user out of HealthVault.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>AUTH</b> - the sign-in page
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at one time.</li>
        ///             <li>forceappauth - force redirect to APPAUTH target once user is authenticated.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEACCOUNT</b> - Allows the user to create a new HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>nsi - no sign in page. The sign in page (where the user enters an email address) is bypassed if set to 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEAPPLICATION</b> - Allows a SODA master application to create a new client application instance.
        ///         <ul>
        ///             <li>publickey - the public key of the new client application instance.  The key
        ///                      must be an X509 certificate that is base64 encoded.</li>
        ///             <li>appid - the GUID that uniquely identifies the SODA master application.  The new application instance will
        ///                      be a child of this master application.</li>
        ///             <li>instanceid - the GUID that will be assigned to the client application.  This ID must be unique
        ///                      for every application instance.</li>
        ///             <li>instancename - A string that identifies the device the new application instance will run on, such
        ///                      as the computer name.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATERECORD</b> - Allows the user to create a new HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>HELP</b> - The HealthVault help page.
        ///         <ul>
        ///             <li>topicid - optional. If not specified the table of contents will be shown.
        ///                 <ul>
        ///                     <li>faq - HealthVault Frequently Asked Questions</li>
        ///                     <li>HelpDirectory - Main HealthVault help page</li>
        ///                     <li>PrivacyPolicy - HealthVault privacy policy</li>
        ///                     <li>Service Agreement - HealthVault Service Agreement</li>
        ///                     <li>CodeofConduct - HealthVault Code of Conduct</li>
        ///                 </ul>
        ///             </li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>MANAGEACCOUNT</b> - Takes the user to a page to manage their account profile.
        ///     <br />The shell does not provide a mechanism to return to the application from the
        ///     account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>RECONCILE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item and transform/merge them into individual HealthVault items in their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>RECORDLIST</b> - A page that lists all records of a HealthVault user.
        ///         <ul>
        ///             <li>appid - optional, the page displays only records which the specified application is authorized to access.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>SHAREDAPPDETAILS</b> - Allows the user to manage application authorization for a HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>SHARERECORD</b> - Allows the user to share a record that they are a custodian of to another HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>VIEWITEMS</b> - Allows a HealthVault user to view all of the items of the specified data type in the their record.
        ///         <ul>
        ///             <li>typeid - data type identifier.</li>
        ///             <li>additem - flag to show the new item dialog for the data type.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        /// </ul>
        /// </param>
        /// 
        /// <param name="targetQuery">
        /// The query string value to pass to the URL to which redirection is 
        /// taking place.
        /// </param>
        /// 
        /// <remarks>
        /// The <paramref name="targetLocation"/> will be passed as the target parameter value to
        /// the redirector URL.
        /// The <paramref name="targetQuery"/> will be URL encoded and passed as the targetqs 
        /// parameter value to the redirector URL.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// If the specific target location causes an improper URL to be
        /// constructed.
        /// </exception>
        /// 
        public static Uri ConstructShellTargetUrl(
            HttpContext context,
            string targetLocation,
            string targetQuery)
        {
            string actionUrlRedirectOverride = GetActionUrlRedirectOverride(context);
            string redirect = actionUrlRedirectOverride == null
                ? null
                : HttpUtility.UrlEncode(actionUrlRedirectOverride);

            return
                HealthServiceLocation.GetHealthServiceShellUrl(
                    targetLocation,
                    targetQuery +
                    "&redirect=" + redirect +
                    "&trm=post");
        }


        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault URL 
        /// redirector.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="targetLocation">
        /// A known constant indicating the internal HealthVault 
        /// service Shell location to redirect to.
        /// 
        /// Locations and their parameters include:
        /// <ul>
        ///     <li><b>APPAUTH</b> - allows the user to select and authorize a health record for use 
        ///             with the specified application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPCONTENT</b> - display application specific content such as privacy  
        ///             statement or terms of use.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>target - used to specify content to display.  The same supported values 
        ///                 as <see cref="HealthServiceActionPage.Action"/> property.
        ///             </li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPREDIRECT</b> - Redirect user to a HealthVault application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the destination application.</li>
        ///             <li>refappid - A GUID that uniquely identifies the referring application.</li>
        ///             <li>target - string used as the "target" parameter when user browser is 
        ///                      redirected to the destination application's action-url.</li>
        ///             <li>targetqs - string used as the "targetqs" parameter when user browser is 
        ///                      redirected to the destination application's action-url</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPSIGNOUT</b> - Signs the user out of HealthVault.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>AUTH</b> - the sign-in page
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at one time.</li>
        ///             <li>forceappauth - force redirect to APPAUTH target once user is authenticated.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEACCOUNT</b> - Allows the user to create a new HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>nsi - no sign in page. The sign in page (where the user enters an email address) is bypassed if set to 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEAPPLICATION</b> - Allows a SODA master application to create a new client application instance.
        ///         <ul>
        ///             <li>publickey - the public key of the new client application instance.  The key
        ///                      must be an X509 certificate that is base64 encoded.</li>
        ///             <li>appid - the GUID that uniquely identifies the SODA master application.  The new application instance will
        ///                      be a child of this master application.</li>
        ///             <li>instanceid - the GUID that will be assigned to the client application.  This ID must be unique
        ///                      for every application instance.</li>
        ///             <li>instancename - A string that identifies the device the new application instance will run on, such
        ///                      as the computer name.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATERECORD</b> - Allows the user to create a new HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>HELP</b> - The HealthVault help page.
        ///         <ul>
        ///             <li>topicid - optional. If not specified the table of contents will be shown.
        ///                 <ul>
        ///                     <li>faq - HealthVault Frequently Asked Questions</li>
        ///                     <li>HelpDirectory - Main HealthVault help page</li>
        ///                     <li>PrivacyPolicy - HealthVault privacy policy</li>
        ///                     <li>Service Agreement - HealthVault Service Agreement</li>
        ///                     <li>CodeofConduct - HealthVault Code of Conduct</li>
        ///                 </ul>
        ///             </li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>MANAGEACCOUNT</b> - Takes the user to a page to manage their account profile.
        ///     <br />The shell does not provide a mechanism to return to the application from the
        ///     account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>RECONCILE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item and transform/merge them into individual HealthVault items in their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>RECORDLIST</b> - A page that lists all records of a HealthVault user.
        ///         <ul>
        ///             <li>appid - optional, the page displays only records which the specified application is authorized to access.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>SHAREDAPPDETAILS</b> - Allows the user to manage application authorization for a HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>SHARERECORD</b> - Allows the user to share a record that they are a custodian of to another HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>VIEWITEMS</b> - Allows a HealthVault user to view all of the items of the specified data type in the their record.
        ///         <ul>
        ///             <li>typeid - data type identifier.</li>
        ///             <li>additem - flag to show the new item dialog for the data type.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        /// </ul>
        /// </param>
        /// 
        /// <param name="targetQuery">
        /// The query string value to pass to the URL to which redirection is 
        /// taking place.
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters passed to the calling application action URL after the
        /// target action is completed in the Shell.
        /// </param>
        /// 
        /// <remarks>
        /// The <paramref name="targetLocation"/> will be passed as the target parameter value to
        /// the redirector URL.
        /// The <paramref name="targetQuery"/> will be URL encoded and passed as the targetqs 
        /// parameter value to the redirector URL.
        /// The <paramref name="actionUrlQueryString"/> will be URL encoded and passed as the actionqs
        /// parameter value to the redirector URL.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// If the specific target location causes an improper URL to be
        /// constructed.
        /// </exception>
        /// 
        public static Uri ConstructShellTargetUrl(
            HttpContext context,
            string targetLocation,
            string targetQuery,
            string actionUrlQueryString)
        {
            string actionUrlRedirectOverride = GetActionUrlRedirectOverride(context);
            string redirect = actionUrlRedirectOverride == null
                ? null
                : HttpUtility.UrlEncode(actionUrlRedirectOverride);

            return
                HealthServiceLocation.GetHealthServiceShellUrl(
                    targetLocation,
                    targetQuery +
                        "&redirect=" + redirect +
                        "&actionqs=" + actionUrlQueryString +
                        "&trm=post");
        }

        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault URL 
        /// redirector.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="targetLocation">
        /// A known constant indicating the internal HealthVault 
        /// service Shell location to redirect to.
        /// 
        /// Locations and their parameters include:
        /// <ul>
        ///     <li><b>APPAUTH</b> - allows the user to select and authorize a health record for use 
        ///             with the specified application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPCONTENT</b> - display application specific content such as privacy  
        ///             statement or terms of use.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>target - used to specify content to display.  The same supported values 
        ///                 as <see cref="HealthServiceActionPage.Action"/> property.
        ///             </li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPREDIRECT</b> - Redirect user to a HealthVault application.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the destination application.</li>
        ///             <li>refappid - A GUID that uniquely identifies the referring application.</li>
        ///             <li>target - string used as the "target" parameter when user browser is 
        ///                      redirected to the destination application's action-url.</li>
        ///             <li>targetqs - string used as the "targetqs" parameter when user browser is 
        ///                      redirected to the destination application's action-url</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>APPSIGNOUT</b> - Signs the user out of HealthVault.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>AUTH</b> - the sign-in page
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at one time.</li>
        ///             <li>forceappauth - force redirect to APPAUTH target once user is authenticated.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEACCOUNT</b> - Allows the user to create a new HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>nsi - no sign in page. The sign in page (where the user enters an email address) is bypassed if set to 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATEAPPLICATION</b> - Allows a SODA master application to create a new client application instance.
        ///         <ul>
        ///             <li>publickey - the public key of the new client application instance.  The key
        ///                      must be an X509 certificate that is base64 encoded.</li>
        ///             <li>appid - the GUID that uniquely identifies the SODA master application.  The new application instance will
        ///                      be a child of this master application.</li>
        ///             <li>instanceid - the GUID that will be assigned to the client application.  This ID must be unique
        ///                      for every application instance.</li>
        ///             <li>instancename - A string that identifies the device the new application instance will run on, such
        ///                      as the computer name.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>CREATERECORD</b> - Allows the user to create a new HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>ismra - the application can use multiple records for the same user at 
        ///                      one time.</li>
        ///             <li>onopt# - A sequence of online optional authorization rule names
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///             <li>offopt# - A sequence of offline optional authorization rule names  
        ///                      identifying which rules to present.  The sequence begins with 1.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>HELP</b> - The HealthVault help page.
        ///         <ul>
        ///             <li>topicid - optional. If not specified the table of contents will be shown.
        ///                 <ul>
        ///                     <li>faq - HealthVault Frequently Asked Questions</li>
        ///                     <li>HelpDirectory - Main HealthVault help page</li>
        ///                     <li>PrivacyPolicy - HealthVault privacy policy</li>
        ///                     <li>Service Agreement - HealthVault Service Agreement</li>
        ///                     <li>CodeofConduct - HealthVault Code of Conduct</li>
        ///                 </ul>
        ///             </li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>MANAGEACCOUNT</b> - Takes the user to a page to manage their account profile.
        ///     <br />The shell does not provide a mechanism to return to the application from the
        ///     account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>RECONCILE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item and transform/merge them into individual HealthVault items in their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>RECORDLIST</b> - A page that lists all records of a HealthVault user.
        ///         <ul>
        ///             <li>appid - optional, the page displays only records which the specified application is authorized to access.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>SHAREDAPPDETAILS</b> - Allows the user to manage application authorization for a HealthVault record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///         The shell does not provide a mechanism to return to the application from the
        ///         account management page, so it is good practice to open the page in a new browser window.
        ///     </li>
        ///     <li><b>SHARERECORD</b> - Allows the user to share a record that they are a custodian of to another HealthVault account.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        ///     <li><b>VIEWITEMS</b> - Allows a HealthVault user to view all of the items of the specified data type in the their record.
        ///         <ul>
        ///             <li>typeid - data type identifier.</li>
        ///             <li>additem - flag to show the new item dialog for the data type.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///         </ul>
        ///     </li>
        /// </ul>
        /// </param>
        /// 
        /// <remarks>
        /// The <paramref name="targetLocation"/> will be passed as the target parameter value to
        /// the redirector URL.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// If the specific target location causes an improper URL to be
        /// constructed.
        /// </exception>
        /// 
        public static Uri ConstructShellTargetUrl(
            HttpContext context,
            string targetLocation)
        {
            string actionUrlRedirectOverride = GetActionUrlRedirectOverride(context);
            string redirect = actionUrlRedirectOverride == null
                ? null
                : HttpUtility.UrlEncode(actionUrlRedirectOverride);

            return
                HealthServiceLocation.GetHealthServiceShellUrl(
                    targetLocation,
                    "&redirect=" + redirect +
                    "&trm=post");
        }

        /// <summary>
        /// Get's the authenticated person's information using the specified authentication token.
        /// </summary>
        /// 
        /// <param name="authToken">
        /// The authentication token for a user. This can be retrieved by extracting the WCToken
        /// query string parameter from the request after the user has been redirected to the
        /// HealthVault AUTH page. See <see cref="RedirectToShellUrl(HttpContext, string)"/> for more information.
        /// </param>
        /// 
        /// <returns>
        /// The information about the logged in person.
        /// </returns>
        /// 
        public static PersonInfo GetPersonInfo(string authToken)
        {
            return GetPersonInfo(
                authToken, 
                HealthWebApplicationConfiguration.Current.ApplicationId);
        }

        /// <summary>
        /// Get's the authenticated person's information using the specified authentication token.
        /// </summary>
        /// 
        /// <param name="authToken">
        /// The authentication token for a user. This can be retrieved by extracting the WCToken
        /// query string parameter from the request after the user has been redirected to the
        /// HealthVault AUTH page. See <see cref="RedirectToShellUrl(HttpContext, string)"/> for more information.
        /// </param>
        /// 
        /// <param name="appId">
        /// The unique identifier for the application.
        /// </param>
        /// 
        /// <returns>
        /// The information about the logged in person.
        /// </returns>
        /// 
        public static PersonInfo GetPersonInfo(string authToken, Guid appId)
        {
            WebApplicationCredential cred = 
                new WebApplicationCredential(
                    appId,
                    authToken,
                    HealthApplicationConfiguration.Current.ApplicationCertificate);

            // set up our cookie
            WebApplicationConnection connection =
                new WebApplicationConnection(appId, cred);

            PersonInfo personInfo = HealthVaultPlatform.GetPersonInfo(connection);
            personInfo.ApplicationSettingsChanged += new EventHandler(OnPersonInfoChanged);
            personInfo.SelectedRecordChanged += new EventHandler(OnPersonInfoChanged);

            return personInfo;
        }

        private static void HandleTokenOnUrl(HttpContext context, bool isLoginRequired, Guid appId)
        {
            string authToken = context.Request.Params[
                QueryStringToken];

            if (!String.IsNullOrEmpty(authToken))
            {
                PersonInfo personInfo = GetPersonInfo(authToken, appId);

                int tokenTtl = -1;
                string tokenTtlString =
                    context.Request.QueryString[
                        PersistentTokenTtl];

                if (!String.IsNullOrEmpty(tokenTtlString))
                {
                    // Note, the tokenTtl parameter is ignored if it's not
                    // an int.
                    Int32.TryParse(tokenTtlString, out tokenTtl);
                }

                SavePersonInfoToCookie(context, personInfo, false, tokenTtl);

                // redirect to fixed-up url
                string newUrl = 
                    StripFromQueryString(
                        context,
                        QueryStringToken,
                        PersistentTokenTtl);

                context.Response.Redirect(newUrl);
            }
        }

        /// <summary>
        /// Removes the specified variables from the query string.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="keys">
        /// variable(s) to remove 
        /// </param>
        /// 
        /// <returns> 
        /// original url without key 
        /// </returns>
        /// 
        private static string StripFromQueryString(
            HttpContext context,
            params string[] keys)
        {
            StringBuilder cleanUrl = new StringBuilder();
            cleanUrl.Append(context.Request.AppRelativeCurrentExecutionFilePath);

            string sep = "?";
            string[] queryKeys = context.Request.QueryString.AllKeys;
            for (int ikey = 0; ikey < queryKeys.Length; ++ikey)
            {
                if (queryKeys[ikey] != null)
                {
                    bool queryKeyMatch = false;

                    for (int index = 0; index < keys.Length; ++index)
                    {
                        if (String.Equals(
                                queryKeys[ikey], 
                                keys[index], 
                                StringComparison.OrdinalIgnoreCase))
                        {
                            queryKeyMatch = true;
                            break;
                        }
                    }

                    if (!queryKeyMatch)
                    {
                        cleanUrl.AppendFormat(
                            "{0}{1}={2}",
                            sep,
                            queryKeys[ikey],
                            context.Server.UrlEncode(context.Request.QueryString[ikey]));
                        sep = "&";
                    }
                }
            }

            return (cleanUrl.ToString());
        }

        private static string UnmarshalCookie(string serializedPersonInfo)
        {
            string personInfoXml;
            int serializationVersion = ParseSerializationVersion(ref serializedPersonInfo);
            switch (serializationVersion)
            {
                case 1:
                    personInfoXml = UnmarshalCookieVersion1(serializedPersonInfo);
                    break;
                case 2:
                    personInfoXml = UnmarshalCookieVersion2(serializedPersonInfo);
                    break;
                default:
                    throw new ArgumentException(
                        ResourceRetriever.FormatResourceString(
                            "UnknownCookieVersion",
                            serializationVersion));
            }

            return personInfoXml;
        }


        /// <summary>
        /// Gets the person's information from the cookie.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <returns>
        /// The person's information that was stored in the cookie or null if the cookie doesn't 
        /// exist. Note, the <see cref="PersonInfo"/> returned may contain an expired authentication
        /// token.
        /// </returns>
        /// 
        public static PersonInfo LoadPersonInfoFromCookie(HttpContext context)
        {
            string serializedPersonInfo = null;

            if (HealthWebApplicationConfiguration.Current.UseAspSession)
            {
                serializedPersonInfo =
                    (String)context.Session[HealthWebApplicationConfiguration.Current.CookieName];
            }
            else
            {
                HttpCookie cookie =
                    context.Request.Cookies[HealthWebApplicationConfiguration.Current.CookieName];

                if (cookie != null)
                {
                    serializedPersonInfo =
                        cookie[WcTokenPersonInfo];
                }
            }

            PersonInfo personInfo = null;
            try
            {
                personInfo = DeserializePersonInfo(serializedPersonInfo);
                if (personInfo != null)
                {
                    personInfo.ApplicationSettingsChanged += new EventHandler(OnPersonInfoChanged);
                    personInfo.SelectedRecordChanged += new EventHandler(OnPersonInfoChanged);
                }
            }
            catch (Exception)
            {
                personInfo = null;  // safety first
                // loading the cookie failed, so remove it on the client
                SavePersonInfoToCookie(context, personInfo, true);
                throw;
            }

            return personInfo;
        }

        /// <summary>
        /// Gets the person's information from the cookie.
        /// </summary>
        /// 
        /// <param name="cookie">
        /// The cookie to load the person's information from
        /// </param>
        /// 
        /// <returns>
        /// The person's information that was stored in the cookie or null if the cookie doesn't
        /// contain the information. Note, the <see cref="PersonInfo"/> returned may contain an 
        /// expired authentication token.
        /// </returns>
        /// 
        public static PersonInfo LoadPersonInfoFromCookie(HttpCookie cookie)
        {
            string serializedPersonInfo = null;
            if (cookie != null)
            {
                serializedPersonInfo =
                    cookie[WcTokenPersonInfo];
            }

            return DeserializePersonInfo(serializedPersonInfo);
        }

        private static PersonInfo DeserializePersonInfo(string serializedPersonInfo)
        {
            if (String.IsNullOrEmpty(serializedPersonInfo)) return null;

            Validator.ThrowInvalidIf(
                serializedPersonInfo.Length > CookieMaxSize,
                "CookieTooBig");

            PersonInfo personInfo = null;

            try
            {
                string personInfoXml = UnmarshalCookie(serializedPersonInfo);

                XPathDocument personDoc 
                    = new XPathDocument(
                        XmlReader.Create(
                            new StringReader(personInfoXml), 
                            SDKHelper.XmlReaderSettings));

                personInfo =
                    PersonInfo.CreateFromXmlExcludeUrl(
                        null, 
                        personDoc.CreateNavigator().SelectSingleNode(
                            "person-info"));
            }
            catch (Exception e)
            {
                MarshallTrace.TraceInformation(
                        "Unmarshalling of cookie failed with exception: "
                        + ExceptionToFullString(e));

                personInfo = null;  // safety first
                throw;
            }
            return personInfo;
        }

        private static int ParseSerializationVersion(ref string serializedPersonInfo)
        {
            int idx = serializedPersonInfo.IndexOf(':');
            if (idx == -1)
            {
                return 1;
            }

            string versionString = serializedPersonInfo.Substring(0, idx);
            serializedPersonInfo = serializedPersonInfo.Substring(idx + 1);

            int version;

            Validator.ThrowArgumentExceptionIf(
                !Int32.TryParse(versionString, out version),
                "version",
                "UnknownCookieVersion");

            return version;
        }

        private static string UnmarshalCookieVersion1(string serializedPersonInfo)
        {
            string[] lengthAndData = serializedPersonInfo.Split(new char[] { '-' }, 2);

            int undeflatedSize = Int32.Parse(lengthAndData[0],CultureInfo.InvariantCulture);
            string deflatedData = lengthAndData[1];

            return Decompress(deflatedData, undeflatedSize);
        }

        private static string UnmarshalCookieVersion2(string serializedPersonInfo)
        {
            string[] lengthAndData = serializedPersonInfo.Split(new char[] { '-' }, 2);
            Int16 unencryptedSize = Int16.Parse(lengthAndData[0], CultureInfo.InvariantCulture);

            byte[] data = Convert.FromBase64String(lengthAndData[1]);

            byte[] iv = new byte[16];
            Buffer.BlockCopy(data, 0, iv, 0, iv.Length);

            SymmetricAlgorithm encryptionAlgorithm = GetEncryptionAlgorithm();
            encryptionAlgorithm.IV = iv;

            byte[] unencryptedData = new byte[unencryptedSize];
            
            MemoryStream dataStream = new MemoryStream(data, iv.Length, data.Length - iv.Length);
            using (CryptoStream cryptoStream = new CryptoStream(dataStream,
                    encryptionAlgorithm.CreateDecryptor(),
                    CryptoStreamMode.Read))
            {
                cryptoStream.Read(unencryptedData, 0, unencryptedData.Length);
            }

            ArraySegment<byte> decompressedData = DecompressInternal(unencryptedData);

            return UTF8Encoding.UTF8.GetString(
                decompressedData.Array,
                decompressedData.Offset,
                decompressedData.Count);            
        }

        private static string MarshalCookieVersion1(string personInfoXml)
        {
            int bufferLength;
            string compressedData = Compress(personInfoXml, out bufferLength);
            return bufferLength.ToString(CultureInfo.InvariantCulture) + "-" + compressedData;
        }

        private static string MarshalCookieVersion2(string personInfoXml)
        {
            SymmetricAlgorithm encryptionAlgorithm = GetEncryptionAlgorithm();
            encryptionAlgorithm.GenerateIV();
            byte[] iv = encryptionAlgorithm.IV;

            int personInfoLength;
            ArraySegment<byte> compressedPersonInfo = CompressInternal(personInfoXml, out personInfoLength);

            MemoryStream output = new MemoryStream();
            using (CryptoStream encryptionStream = new CryptoStream(
                output,
                encryptionAlgorithm.CreateEncryptor(),
                CryptoStreamMode.Write))
            {
                encryptionStream.Write(iv, 0, iv.Length);
                encryptionStream.Write(compressedPersonInfo.Array, compressedPersonInfo.Offset, (int)compressedPersonInfo.Count);
                encryptionStream.FlushFinalBlock();

                return personInfoLength + "-" + Convert.ToBase64String(output.GetBuffer(), 0, (int)output.Length);
            }
        }

        private static SymmetricAlgorithm GetEncryptionAlgorithm()
        {
            Rijndael encryptionAlgorithm = Rijndael.Create();
            encryptionAlgorithm.BlockSize = 128;
            encryptionAlgorithm.Key = HealthWebApplicationConfiguration.Current.CookieEncryptionKey;

            return encryptionAlgorithm;
        }

        private static string ExceptionToFullString(Exception e)
        {
            string eString = e.ToString();
            StringBuilder buffer = new StringBuilder(
                    eString,
                    eString.Length + (e.InnerException != null ? 1024 : 0));

            e = e.InnerException;
            while (e != null)
            {
                buffer.AppendFormat("\r\n" + e.ToString());
                e = e.InnerException;
            }

            return buffer.ToString();
        }

        private static TraceSource MarshallTrace 
            = new TraceSource("MarshallSource");

        /// <summary>
        /// Compress incoming string.
        /// </summary>
        /// 
        /// <param name="data">
        /// String to be compressed.
        /// </param>
        /// <param name="bufferLength">
        /// The length of the incoming string in bytes.
        /// </param>
        /// 
        /// <returns>
        /// Base 64 string of compressed data.
        /// </returns>
        /// 
        public static string Compress(string data, out int bufferLength)
        {
            ArraySegment<byte> compressedBytes = CompressInternal(data, out bufferLength);
            return Convert.ToBase64String(compressedBytes.Array, compressedBytes.Offset, compressedBytes.Count);
        }

        private static ArraySegment<byte> CompressInternal(string data, out int length)
        {
            MemoryStream ms = new MemoryStream();
            using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Compress, true))
            {
                byte[] b = new UTF8Encoding(false, true).GetBytes(data);
                length = b.Length;

                ds.Write(b, 0, b.Length);
            }
            return new ArraySegment<byte>(ms.GetBuffer(), 0, (int)ms.Length);
        }

        /// <summary>
        /// Compress incoming string.
        /// </summary>
        /// 
        /// <param name="data">
        /// String to be compressed.
        /// </param>
        /// 
        /// <returns>
        /// Base 64 string of compressed data.
        /// </returns>
        /// 
        public static string Compress(string data)
        {
            int bufferLength;
            return Compress(data, out bufferLength);
        }

        /// <summary>
        /// Decompress a compressed string.
        /// </summary>
        /// 
        /// <param name="compressedData">
        /// Base 64 String of compressed data.
        /// </param>
        /// 
        /// <returns>
        /// Uncompressed string.
        /// </returns>
        /// 
        public static string Decompress(string compressedData)
        {
            return Decompress(compressedData, -1);
        }

        /// <summary>
        /// Decompress a compressed string.
        /// </summary>
        /// 
        /// <param name="compressedData">
        /// Base 64 string of compressed data.
        /// </param>
        /// <param name="decompressedDataLength">
        /// Length of uncompressed data.
        /// </param>
        /// 
        /// <returns>
        /// Uncompressed string.
        /// </returns>
        /// 
        private static string Decompress(string compressedData, int decompressedDataLength)
        {
            if (String.IsNullOrEmpty(compressedData))
            {
                return String.Empty;
            }

            byte[] stringBytes = Convert.FromBase64String(compressedData);

            ArraySegment<byte> decompressedBytes = DecompressInternal(stringBytes, decompressedDataLength);
           
            return UTF8Encoding.UTF8.GetString(
                decompressedBytes.Array, 
                decompressedBytes.Offset, 
                decompressedBytes.Count);
        }

        private static ArraySegment<byte> DecompressInternal(byte[] compressedData)
        {
            return DecompressInternal(compressedData, -1);
        }

        private static ArraySegment<byte> DecompressInternal(byte[] compressedData, int decompressedLength)
        {
            MemoryStream ms = new MemoryStream(compressedData, 0, compressedData.Length);

            using (DeflateStream ds = new DeflateStream(ms, CompressionMode.Decompress, false))
            {
                if (decompressedLength != -1)
                {
                    byte[] buffer = new byte[decompressedLength];
                    ds.Read(buffer, 0, decompressedLength);
                    return new ArraySegment<byte>(buffer, 0, decompressedLength);
                }
                else
                {
                    return ReadToStreamEnd(ds);
                }
            }
        }

        private static ArraySegment<byte> ReadToStreamEnd(Stream stream)
        {            
            int bytesRead;
            int totalBytesRead = 0;
            byte[] readBuffer = new byte[4096];
            
            while ((bytesRead = stream.Read(readBuffer, totalBytesRead, readBuffer.Length - totalBytesRead)) > 0)
            {
                totalBytesRead += bytesRead;

                if (totalBytesRead == readBuffer.Length)
                {
                    int nextByte = stream.ReadByte();

                    if (nextByte != -1)
                    {
                        Validator.ThrowInvalidIf(
                            readBuffer.Length > 32768,
                            "DecompressionSizeExceeded");

                        byte[] temp = new byte[readBuffer.Length * 2];
                        Buffer.BlockCopy(readBuffer, 0, temp, 0, readBuffer.Length);
                        Buffer.SetByte(temp, totalBytesRead, (byte)nextByte);
                        readBuffer = temp;
                        totalBytesRead++;
                    }
                }
            }
            return new ArraySegment<byte>(readBuffer, 0, totalBytesRead);
        }

        private static string PersonInfoAsCookie(PersonInfo personInfo)
        {
            return PersonInfoAsCookie(personInfo, true);
        }

        private static string PersonInfoAsCookie(PersonInfo personInfo, bool keepSizeUnderLimit)
        {
            string cookie = PersonInfoAsCookie(personInfo, PersonInfo.CookieOptions.Default);

            if (cookie.Length <= CookieMaxSize || !keepSizeUnderLimit)
            {
                return cookie;
            }

            // The cookie is too big to fit. Try it without app settings...
            cookie = PersonInfoAsCookie(personInfo, PersonInfo.CookieOptions.MinimizeApplicationSettings);
            if (cookie.Length <= CookieMaxSize)
            {
                return cookie;
            }

            // That didn't help. Try it with minimal records...
            cookie = PersonInfoAsCookie(personInfo, PersonInfo.CookieOptions.MinimizeRecords);
            if (cookie.Length <= CookieMaxSize)
            {
                return cookie;
            }

            // Reduce both...
            cookie = PersonInfoAsCookie(
                            personInfo, 
                            PersonInfo.CookieOptions.MinimizeApplicationSettings | 
                            PersonInfo.CookieOptions.MinimizeRecords);
            return cookie;
        }

        private static string PersonInfoAsCookie(PersonInfo personInfo, PersonInfo.CookieOptions cookieOptions)
        {
            string personInfoXml = personInfo.GetXmlForCookie(cookieOptions);

            int version = GetMarshalCookieVersion();
            switch (version)
            {
                case 1:
                    return "1:" + MarshalCookieVersion1(personInfoXml);
                case 2:
                    return "2:" + MarshalCookieVersion2(personInfoXml);
                default:
                    throw new ArgumentException(
                        ResourceRetriever.FormatResourceString(
                            "UnknownCookieVersion",
                            version));
            }
        }

        private static int GetMarshalCookieVersion()
        {
            if (HealthWebApplicationConfiguration.Current.CookieEncryptionKey != null)
            {
                return 2;
            }
            
            return 1;
        }

        /// <summary>
        /// Stores the specified person's information in the cookie.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="personInfo">
        /// The person's information to store. If null and <paramref name="clearIfNull"/> is true,
        /// the cookie will be cleared and the person will be logged off from HealthVault.
        /// </param>
        /// 
        /// <param name="clearIfNull">
        /// If true and <paramref name="personInfo"/> is null, the cookie will be cleared and the
        /// person will be logged off from HealthVault.
        /// </param>
        /// 
        public static void SavePersonInfoToCookie(
            HttpContext context,
            PersonInfo personInfo,
            bool clearIfNull)
        {
            SavePersonInfoToCookie(context, personInfo, clearIfNull, -1);
        }

        private static void SavePersonInfoToCookie(
            HttpContext context, 
            PersonInfo personInfo, 
            bool clearIfNull, 
            int cookieTimeout)
        {
            if (personInfo != null || clearIfNull)
            {
                if (HealthWebApplicationConfiguration.Current.UseAspSession)
                {
                    if (personInfo == null)
                    {
                        context.Session.Remove(HealthWebApplicationConfiguration.Current.CookieName);
                    }
                    else
                    {
                        context.Session[HealthWebApplicationConfiguration.Current.CookieName] 
                            = PersonInfoAsCookie(personInfo);
                    }
                }
                else
                {
                    HttpCookie existingCookie =
                        context.Request.Cookies[
                            HealthWebApplicationConfiguration.Current.CookieName];
                    HttpCookie cookie = 
                        SavePersonInfoToCookie(personInfo, existingCookie, cookieTimeout);

                    context.Response.Cookies.Remove(
                            HealthWebApplicationConfiguration.Current.CookieName);
                    context.Response.Cookies.Add(cookie);
                }
            }
        }

        /// <summary>
        /// Stores the specified person's information in the cookie.
        /// </summary>
        /// 
        /// <param name="personInfo">
        /// The authenticated person's information.
        /// </param>
        /// 
        /// <returns>
        /// A cookie containing the person's information.
        /// </returns>
        /// 
        /// <remarks>
        /// If <paramref name="personInfo"/> is null, the returned cookie will have an
        /// expiration date in the past, and adding it to a response would result in the cookie
        /// being cleared.
        /// </remarks>
        /// 
        public static HttpCookie SavePersonInfoToCookie(PersonInfo personInfo)
        {
            return SavePersonInfoToCookie(personInfo, null, -1);
        }

        /// <summary>
        /// Stores the specified person's information in the cookie.
        /// </summary>
        /// 
        /// <param name="personInfo">
        /// The authenticated person's information.
        /// </param>
        /// 
        /// <param name="existingCookie">
        /// The existing cooke containing the person's information. The expiration date of this 
        /// cookie will be used as the expiration date of the returned cookie.
        /// </param>
        /// 
        /// <returns>
        /// A cookie containing the person's information.
        /// </returns>
        /// 
        /// <remarks>
        /// If <paramref name="personInfo"/> is null, the returned cookie will have an
        /// expiration date in the past, and adding it to a response would result in the cookie
        /// being cleared.
        /// </remarks>
        /// 
        public static HttpCookie SavePersonInfoToCookie(
            PersonInfo personInfo, 
            HttpCookie existingCookie)
        {
            return SavePersonInfoToCookie(personInfo, existingCookie, -1);
        }

        private static HttpCookie SavePersonInfoToCookie(
            PersonInfo personInfo,
            HttpCookie existingCookie,
            int cookieTimeout)
        {
            HttpCookie cookie =
                new HttpCookie(HealthWebApplicationConfiguration.Current.CookieName);
            cookie.HttpOnly = true;
            cookie.Secure = HealthWebApplicationConfiguration.Current.UseSslForSecurity;

            if (personInfo == null)
            {
                cookie.Expires = DateTime.Now.AddDays(-1);
            }
            else
            {
                if (cookieTimeout > 0)
                {
                    // If a greater than zero cookie timeout is in the
                    // query, then it means the user wishes the
                    // persist their auth token. Use this value.
                    cookieTimeout = Math.Min(
                        cookieTimeout,
                        HealthWebApplicationConfiguration.Current.MaxCookieTimeoutMinutes);

                    // Save the absolute expiration in the cookie. This
                    // is when the auth token itself expires.
                    // Therefore, we do not want this to be a sliding
                    // expiration. We want the cookie expiration to
                    // match the auth token expiration. Whenever the
                    // cookie is re-written, we need to preserve the
                    // expiration date of that cookie.
                    cookie.Expires =
                        DateTime.Now.AddMinutes(cookieTimeout);
                    cookie[WcTokenExpiration] =
                        cookie.Expires.ToUniversalTime().ToString();
                }
                else if (existingCookie != null)
                {
                    // If we do not have an explicit cookie timeout to
                    // set but have an existing cookie, then we want
                    // to preserve the expiration on the new cookie.
                    string expirationString =
                        existingCookie[WcTokenExpiration];

                    // If the expiration was not set in the existing
                    // cookie, then it is a session cookie. Do not
                    // overwrite the expiration on it.
                    if (!String.IsNullOrEmpty(expirationString))
                    {
                        DateTime expiration;

                        if (!DateTime.TryParse(expirationString, out expiration))
                        {
                            // Somehow the expiration cookie value
                            // failed to parse. Set it to the
                            // web.config timeout value.
                            cookieTimeout =
                                HealthWebApplicationConfiguration.Current.CookieTimeoutMinutes;

                            if (cookieTimeout > 0)
                            {
                                cookie.Expires =
                                    DateTime.Now.AddMinutes(cookieTimeout);
                                cookie[WcTokenExpiration] =
                                    cookie.Expires.ToUniversalTime().ToString();
                            }
                        }
                        else
                        {
                            cookie.Expires = expiration.ToLocalTime();
                            cookie[WcTokenExpiration] =
                                cookie.Expires.ToUniversalTime().ToString();
                        }
                    }
                }
                else
                {
                    // We do not have an explicit cookie timeout to
                    // set and no exiting cookie. Set the cookie
                    // timeout to the one in web.config.
                    cookieTimeout =
                        HealthWebApplicationConfiguration.Current.CookieTimeoutMinutes;

                    if (cookieTimeout > 0)
                    {
                        // We only set the expiration if it is not a
                        // session cookie.
                        // NOTE: We do not write the expiration date
                        // out to the cookie to preserve existing
                        // behavior.
                        cookie.Expires = DateTime.Now.AddMinutes(cookieTimeout);
                    }
                }

                cookie[WcTokenPersonInfo]
                    = PersonInfoAsCookie(personInfo);
            }

            if (!String.IsNullOrEmpty(HealthWebApplicationConfiguration.Current.CookieDomain))
            {
                cookie.Domain = HealthWebApplicationConfiguration.Current.CookieDomain;
            }

            if (!String.IsNullOrEmpty(HealthWebApplicationConfiguration.Current.CookiePath))
            {
                cookie.Path = HealthWebApplicationConfiguration.Current.CookiePath;
            }

            return cookie;
        }

        private static string GetActionUrlRedirectOverride(HttpContext context)
        {
            Uri actionUrlRedirectOverride =
                HealthWebApplicationConfiguration.Current.ActionUrlRedirectOverride;

            if (actionUrlRedirectOverride == null) return null;

            string actionUrlRedirectOverrideString = actionUrlRedirectOverride.OriginalString;
            if (actionUrlRedirectOverride.IsAbsoluteUri)
            {
                return actionUrlRedirectOverrideString;
            }

            Uri currentRequest = context.Request.Url;
            StringBuilder buffer = new StringBuilder(
                                        currentRequest.Scheme 
                                        + Uri.SchemeDelimiter 
                                        + currentRequest.Authority, 
                                        128);
            buffer.Append(context.Request.ApplicationPath);
            if (buffer[buffer.Length - 1] != '/'
                && !actionUrlRedirectOverrideString.StartsWith("/"))
            {
                buffer.Append("/");
            }
            buffer.Append(actionUrlRedirectOverrideString);

            return buffer.ToString();
        }

        /// <summary>
        /// Redirects the caller's browser to the logon page for 
        /// authentication.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="isMra">
        /// Whether this application simultaneously deals with multiple records
        /// for the same person.
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters to pass to the signin action URL after
        /// signin.
        /// </param>
        /// 
        /// <remarks>
        /// After the user successfully authenticates, they get redirected 
        /// to the action url for which the target is set to either
        /// AppAuthSuccess or AppAuthRejected depending on whether the user
        /// authorized one or more records for use with the application, 
        /// with the authentication token in the query
        /// string. This is stripped out and used to populate HealthVault
        /// data for the page.
        /// </remarks>
        /// 
        public static void RedirectToLogOn(
            HttpContext context,
            bool isMra, 
            string actionUrlQueryString)
        {
            RedirectToLogOn(context, isMra, actionUrlQueryString, null /* signupCode */);
        }


        /// <summary>
        /// Redirects the caller's browser to the logon page for 
        /// authentication.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="isMra">
        /// Whether this application simultaneously deals with multiple records
        /// for the same person.
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters to pass to the signin action URL after
        /// signin.
        /// </param>
        /// 
        /// <param name="signupCode">
        /// The signup code for creating a HealthVault account.  This is required
        /// for applications in locations with limited access to HealthVault.
        /// Signup codes may be obtained from
        /// <see cref="Microsoft.Health.ApplicationConnection.NewSignupCode" />,
        /// <see cref="Microsoft.Health.PatientConnect.PatientConnection.Create" />,
        /// <see cref="Microsoft.Health.Package.ConnectPackage.Create(Microsoft.Health.Web.OfflineWebApplicationConnection, string, string, string, string, System.Collections.Generic.IList&lt;Microsoft.Health.HealthRecordItem&gt;)" />,
        /// <see cref="Microsoft.Health.Package.ConnectPackage.Create(Microsoft.Health.Web.OfflineWebApplicationConnection, string, string, string, Microsoft.Health.ItemTypes.PasswordProtectedPackage)" />,
        /// <see cref="Microsoft.Health.Package.ConnectPackage.Create(Microsoft.Health.Web.OfflineWebApplicationConnection, string, string, string, string, Microsoft.Health.ItemTypes.PasswordProtectedPackage)" />,
        /// <see cref="Microsoft.Health.Package.ConnectPackage.CreatePackage" />,
        /// and <see cref="Microsoft.Health.Package.ConnectPackage.AllocatePackageId" />
        /// </param>
        /// 
        /// <remarks>
        /// After the user successfully authenticates, they get redirected 
        /// to the action url for which the target is set to either
        /// AppAuthSuccess or AppAuthRejected depending on whether the user
        /// authorized one or more records for use with the application, 
        /// with the authentication token in the query
        /// string. This is stripped out and used to populate HealthVault
        /// data for the page.
        /// </remarks>
        /// 
        public static void RedirectToLogOn(
            HttpContext context,
            bool isMra,
            string actionUrlQueryString,
            string signupCode)
        {
            string actionUrlRedirectOverride = GetActionUrlRedirectOverride(context);
            string redirect = actionUrlRedirectOverride == null
                ? null
                : context.Server.UrlEncode(actionUrlRedirectOverride);
            string actionqs = String.IsNullOrEmpty(actionUrlQueryString)
                ? null
                : context.Server.UrlEncode(actionUrlQueryString);

            StringBuilder sb = new StringBuilder();
            if (redirect != null)
            {
                sb.AppendFormat("&redirect={0}", redirect);
            }

            if (actionqs != null)
            {
                sb.AppendFormat("&actionqs={0}", actionqs);
            }

            if (isMra)
            {
                sb.Append("&ismra=true");
            }

            if (signupCode != null)
            {
                sb.AppendFormat("&signupcode={0}", signupCode);
            }

            sb.Append("&trm=post");

            context.Response.Redirect(
                HealthWebApplicationConfiguration.Current.HealthVaultShellAuthenticationUrl
                + context.Server.UrlEncode(sb.ToString()));
        }

        /// <summary>
        /// Redirects the caller's browser to the logon page for 
        /// authentication.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="isMra">
        /// Whether this application simultaneously deals with multiple records
        /// for the same person.
        /// </param>
        /// 
        /// <remarks>
        /// After the user successfully authenticates, they get redirected 
        /// to the action url for which the target is set to either
        /// AppAuthSuccess or AppAuthRejected depending on whether the user
        /// authorized one or more records for use with the application, with 
        /// the authentication token in the query
        /// string. This is stripped out and used to populate HealthVault
        /// data for the page.
        /// </remarks>
        /// 
        public static void RedirectToLogOn(HttpContext context, bool isMra)
        {
            RedirectToLogOn(context, isMra, context.Request.Url.PathAndQuery);
        }

        /// <summary>
        /// Redirects the caller's browser to the logon page for 
        /// authentication.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <remarks>
        /// After the user successfully authenticates, they get redirected 
        /// back to the action url for which the target is set to either
        /// AppAuthSuccess or AppAuthRejected depending on whether the user
        /// authorized one or more records for use with the application, 
        /// with the authentication token in the query
        /// string. This is stripped out and used to populate HealthVault
        /// data for the page.<br/>
        /// <br/>
        /// This overload assumes that the applications does not simultaneously
        /// deal with multiple records for the same person i.e. isMra is false.
        /// </remarks>
        /// 
        public static void RedirectToLogOn(HttpContext context)
        {
            RedirectToLogOn(context, false);
        }

        /// <summary>
        /// Signs the person out and cleans up the HealthVault session 
        /// information.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <remarks>
        /// This should only be used by the HealthVault Shell.
        /// </remarks>
        /// 
        private static void LogOff(HttpContext context)
        {
            SavePersonInfoToCookie(context, null, true);
        }

        /// <summary>
        /// Signs the person out, cleans up the HealthVault session 
        /// information, and redirects the user's browser to the signout action 
        /// URL.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        public static void SignOut(HttpContext context)
        {
            SignOut(context, null);
        }

        /// <summary>
        /// Signs the person out, cleans up the HealthVault session 
        /// information, and redirects the user's browser to the signout action 
        /// URL.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="appId">
        /// The unique identifier for the application.
        /// </param>
        /// 
        public static void SignOut(HttpContext context, Guid appId)
        {
            SignOut(context, null, appId);
        }

        /// <summary>
        /// Signs the person out, cleans up the HealthVault session 
        /// information, and redirects the user's browser to the signout action 
        /// URL with the specified querystring parameter if any.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters to pass to the signout action URL after
        /// cleaning up data.
        /// </param>
        /// 
        public static void SignOut(HttpContext context, string actionUrlQueryString)
        {
            SignOut(
                context, 
                actionUrlQueryString,
                HealthWebApplicationConfiguration.Current.ApplicationId);
        }


        /// <summary>
        /// Signs the person out, cleans up the HealthVault session 
        /// information, and redirects the user's browser to the signout action 
        /// URL with the specified querystring parameter if any.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters to pass to the signout action URL after
        /// cleaning up data.
        /// </param>
        /// 
        /// <param name="appId">
        /// The unique identifier of the application.
        /// </param>
        /// 
        public static void SignOut(HttpContext context, string actionUrlQueryString, Guid appId)
        {
            SignOut(context, actionUrlQueryString, appId, null);
        }

        /// <summary>
        /// Signs the person out, cleans up the HealthVault session 
        /// information, and redirects the user's browser to the signout action 
        /// URL with the specified querystring parameter (including user's credential token) if any.
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="actionUrlQueryString">
        /// The query string parameters to pass to the signout action URL after
        /// cleaning up data.
        /// </param>
        /// 
        /// <param name="appId">
        /// The unique identifier of the application.
        /// </param>
        /// 
        /// <param name="credentialToken">
        /// The user's credential token to sign out.
        /// </param>
        /// 
        public static void SignOut(HttpContext context, string actionUrlQueryString, Guid appId, string credentialToken)
        {
            LogOff(context);

            string actionUrlRedirectOverride = GetActionUrlRedirectOverride(context);
            string redirect = actionUrlRedirectOverride == null
                ? null
                : context.Server.UrlEncode(actionUrlRedirectOverride);
            string actionqs = String.IsNullOrEmpty(actionUrlQueryString)
                ? null
                : context.Server.UrlEncode(actionUrlQueryString);

            string signOutUrl =
                HealthServiceLocation.GetShellRedirectorUrl(
                    HealthWebApplicationConfiguration.Current.HealthVaultShellUrl).ToString() +
                "APPSIGNOUT&targetqs=" + 
                    context.Server.UrlEncode(
                        "?appid=" + appId +
                        (redirect != null ? "&redirect=" + redirect : String.Empty)
                        + (actionqs != null ? "&actionqs=" + actionqs : String.Empty)
                        + (String.IsNullOrEmpty(credentialToken) ? String.Empty : "&credtoken=" + context.Server.UrlEncode(credentialToken)));

            context.Response.Redirect(signOutUrl);
        }

        /// <summary>
        /// Redirects application to Shell help page
        /// </summary>
        /// 
        /// <param name="context">
        /// The current request context.
        /// </param>
        /// 
        /// <param name="topic">
        /// Optional topic string. For example, "faq" would redirect the user's browser to the
        /// HealthVault frequently asked questions.
        /// </param>
        /// 
        public static void GotoHelp(HttpContext context, string topic)
        {
            string targetQuery = String.IsNullOrEmpty(topic) 
                                    ? String.Empty : "?topicid=" + topic + "&";

            Uri helpUrl = ConstructShellTargetUrl(context, "HELP", targetQuery);

            context.Response.Redirect(helpUrl.ToString());
        }
    }
}
