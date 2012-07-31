// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Web;
using Microsoft.Health;

namespace Microsoft.Health
{
    /// <summary>
    /// Provides methods that retrieve URLs of important locations for the 
    /// HealthVault service.
    /// </summary>
    /// 
    public static class HealthServiceLocation
    {
        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault service Shell
        /// URL redirector, given the specified location.
        /// </summary>
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
        ///                 as <see cref="T:Microsoft.Health.Web.HealthServiceActionPage.Action"/> property.
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
        ///     <li><b>RECONCILECOMPLETE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item that have already been transformed/merged into their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///             <li>relto - CCR/CCD item identifier.</li>
        ///             <li>reltotypeid - CCR/CCD typeidentifier.</li>
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
        /// The <paramref name="targetLocation"/> is passed as the target 
        /// parameter value to the redirector URL.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// The specific target location constructs an improper URL.
        /// </exception>
        /// 
        public static Uri GetHealthServiceShellUrl(string targetLocation)
        {
            return GetHealthServiceShellUrl(
                HealthServiceLocation.GetShellRedirectorUrl(
                    HealthApplicationConfiguration.Current.HealthVaultShellUrl),
                targetLocation);
        }

        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault service Shell
        /// URL redirector, given the specified location.
        /// </summary>
        /// 
        /// <param name="shellUrl">
        /// The HealthVault Shell redirector URL.
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
        ///                 as <see cref="T:Microsoft.Health.Web.HealthServiceActionPage.Action"/> property.
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
        ///     <li><b>RECONCILECOMPLETE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item that have already been transformed/merged into their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///             <li>relto - CCR/CCD item identifier.</li>
        ///             <li>reltotypeid - CCR/CCD typeidentifier.</li>
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
        /// The <paramref name="targetLocation"/> is passed as the target 
        /// parameter value to the redirector URL.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// The specific target location constructs an improper URL.
        /// </exception>
        /// 
        public static Uri GetHealthServiceShellUrl(
            Uri shellUrl,
            string targetLocation)
        {
            string targetUrl =
                String.Join(String.Empty,
                    new string[] 
                    {
                        shellUrl.ToString(),
                        targetLocation,
                    }
                );
            return new Uri(targetUrl);
        }

        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault service
        /// Shell URL redirector, given the specified location and query.
        /// </summary>
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
        ///                 as <see cref="T:Microsoft.Health.Web.HealthServiceActionPage.Action"/> property.
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
        ///     <li><b>RECONCILECOMPLETE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item that have already been transformed/merged into their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///             <li>relto - CCR/CCD item identifier.</li>
        ///             <li>reltotypeid - CCR/CCD typeidentifier.</li>
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
        /// The <paramref name="targetLocation"/> is passed as the target 
        /// parameter value to the redirector URL.
        /// The <paramref name="targetQuery"/> is URL-encoded and 
        /// passed to the redirector URL as the target query string parameter 
        /// value.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// The specific target location constructs an improper URL.
        /// </exception>
        /// 
        public static Uri GetHealthServiceShellUrl(
            string targetLocation,
            string targetQuery)
        {
            return GetHealthServiceShellUrl(
                GetShellRedirectorUrl(
                    HealthApplicationConfiguration.Current.HealthVaultShellUrl),
                targetLocation,
                targetQuery);
        }

        /// <summary>
        /// Constructs a URL to be redirected to via the HealthVault service
        /// Shell URL redirector, given the specified location and query.
        /// </summary>
        /// 
        /// <param name="shellUrl">
        /// The HealthVault Shell redirector URL.
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
        ///                 as <see cref="T:Microsoft.Health.Web.HealthServiceActionPage.Action"/> property.
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
        ///     <li><b>RECONCILECOMPLETE</b> - A page that allows a HealthVault user to review the individual 
        ///                            data elements within a CCR or CCD item that have already been transformed/merged into their record.
        ///         <ul>
        ///             <li>appid - A GUID that uniquely identifies the application.</li>
        ///             <li>extrecordid - record identifier.</li>
        ///             <li>thingid - CCR/CCD item identifier.</li>
        ///             <li>relto - CCR/CCD item identifier.</li>
        ///             <li>reltotypeid - CCR/CCD typeidentifier.</li>
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
        /// The <paramref name="targetLocation"/> is passed as the target 
        /// parameter value to the redirector URL.
        /// The <paramref name="targetQuery"/> is URL-encoded and 
        /// passed to the redirector URL as the target query string parameter 
        /// value.
        /// </remarks>
        /// 
        /// <returns>
        /// The constructed URL.
        /// </returns>
        /// 
        /// <exception cref="UriFormatException">
        /// The specific target location constructs an improper URL.
        /// </exception>
        /// 
        public static Uri GetHealthServiceShellUrl(
            Uri shellUrl,
            string targetLocation,
            string targetQuery)
        {
            string url =
                String.Join(
                    String.Empty,
                    new string[] 
                    {
                        shellUrl.ToString(),
                        targetLocation,
                        "&targetqs=",
                        targetQuery == null
                            ? String.Empty
                            : HttpUtility.UrlEncode(targetQuery),
                        "&trm=post"
                    });

            return new Uri(url);
        }

        internal static Uri GetServiceBaseUrl(Uri healthServiceUrl)
        {
            string url = healthServiceUrl.OriginalString;

            int index = url.LastIndexOf('/');
            if (index > 0)
            {
                url = url.Substring(0, index);
            }
            return new Uri(url);
        }

        internal static Uri GetShellRedirectorUrl(Uri shellUrl)
        {
            Uri shellRedirectorUrl =
                new Uri(shellUrl, ShellRedirectorLocation);
            return shellRedirectorUrl;
        }
        private const string ShellRedirectorLocation = "redirect.aspx?target=";

        /// <summary>
        /// Shell auth page location including the application id.
        /// </summary>
        /// 
        internal static Uri GetShellAuthenticationUrl(Uri shellUrl, Guid applicationId)
        {
            string url =
                String.Join(String.Empty,
                    new string[] 
                        {
                            GetShellRedirectorUrl(shellUrl).OriginalString,
                            "AUTH&targetqs=",
                            HttpUtility.UrlEncode("?appid="),
                            applicationId.ToString()
                        }
                    );
            return new Uri(url);
        }
    }
}

