// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Health.Authentication;

using Microsoft.Health;
using Microsoft.Health.Web;

namespace Microsoft.Health
{

    /// <summary>
    /// Represents a saved HealthVault service method invocation that 
    /// can be invoked any time by anyone through a query-specific URL.
    /// </summary>
    /// 
    /// <remarks>
    /// <see cref="OpenQuery"/> instances are inherently insecure. Therefore, 
    /// store the URL to the instance securely and do not share it.
    /// 
    /// An <see cref="OpenQuery"/> is created using the static 
    /// <see cref="NewQuery(Microsoft.Health.AuthenticatedConnection, Microsoft.Health.HealthRecordSearcher)"/>
    /// or 
    /// <see cref="NewQuery(Microsoft.Health.AuthenticatedConnection, Microsoft.Health.HealthRecordSearcher, string)"/>
    /// method, which returns an <see cref="OpenQuery"/> instance that contains the query ID and
    /// URL to the <see cref="OpenQuery"/>. Reference an existing <see cref="OpenQuery"/> 
    /// using one of the class constructors. The query ID can either be
    /// explicitly specified or parsed from the URL, depending on which
    /// constructor is used.
    /// </remarks>
    /// 
    public class OpenQuery
    {
        #region Ctors
        /// <summary>
        /// Creates a new instance of the <see cref="OpenQuery"/> class for the 
        /// specified URL, represented by a string.
        /// </summary>
        /// 
        /// <param name="url">
        /// A string representing the URL of an existing <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <remarks>
        /// Constructing an instance of the class does not create an open
        /// query. Instead, it attaches the instance to an existing open query
        /// specified by the <paramref name="url"/>.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="url"/> is <b>null</b> or empty.
        /// </exception>
        /// 
        /// <exception cref="UriFormatException">
        /// The <paramref name="url"/> parameter is a relative path.
        /// -or-
        /// The path is not a URL.
        /// -or-
        /// The host name specified is not valid.
        /// -or-
        /// The file name specified is not valid.
        /// -or-
        /// The port number specified is not valid or cannot be parsed.
        /// -or-
        /// The length exceeds 65534 characters.
        /// -or-
        /// There is an invalid character sequence.
        /// </exception>
        /// 
        public OpenQuery(string url) :
            this(new Uri(url, UriKind.Absolute))
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="OpenQuery"/> class for the 
        /// specified URL.
        /// </summary>
        /// 
        /// <param name="url">
        /// A URI representing the URL of an existing <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <remarks>
        /// Constructing an instance of the class does not create an open
        /// query. Instead, it attaches the instance to an existing open query
        /// specified by the <paramref name="url"/>.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="url"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="UriFormatException">
        /// The <paramref name="url"/> parameter is a relative path.
        /// -or-
        /// The path is not a URL.
        /// -or-
        /// The host name specified is not valid.
        /// -or-
        /// The file name specified is not valid.
        /// -or-
        /// The port number specified is not valid or cannot be parsed.
        /// -or-
        /// The length exceeds 65534 characters.
        /// -or-
        /// There is an invalid character sequence.
        /// </exception>
        /// 
        public OpenQuery(Uri url)
        {
            Validator.ThrowIfArgumentNull(url, "url", "UrlSetRequiresValue");

            _url = url;

            // Parse the query portion of the URL to get the ID parameter
            int idIndex =
                _url.Query.IndexOf(
                    "id=",
                    StringComparison.OrdinalIgnoreCase);

            if (idIndex == -1)
            {
                throw new FormatException(
                    ResourceRetriever.GetResourceString("UrlDoesNotContainQueryId"));
            }

            // The guid of the ID starts after the equals and goes for
            // 36 characters.

            try
            {
                string idString = _url.Query.Substring(idIndex + 3, 36);
                _id = new Guid(idString);
            }
            catch (ArgumentOutOfRangeException)
            {
                throw new FormatException(
                    ResourceRetriever.GetResourceString("UrlDoesNotContainQueryId"));
            }
            catch (FormatException)
            {
                throw new FormatException(
                    ResourceRetriever.GetResourceString("UrlDoesNotContainQueryId"));
            }
        }

        /// <summary>
        /// Creates a new instance of the <see cref="OpenQuery"/> class for the 
        /// specified query ID.
        /// </summary>
        /// 
        /// <param name="queryId">
        /// The ID of an existing <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <remarks>
        /// Constructing an instance of the class does not create an open
        /// query. Instead, it attaches the instance to an existing open query
        /// specified by the <paramref name="queryId"/>.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="queryId"/> parameter is empty.
        /// </exception>
        /// 
        public OpenQuery(Guid queryId)
        {
            Validator.ThrowArgumentExceptionIf(
                queryId == Guid.Empty,
                "queryId",
                "QueryIdInvalid");

            _id = queryId;
        }
        #endregion Ctors

        #region Public properties

        /// <summary>
        /// Gets or sets the URL of the <see cref="OpenQuery"/> instance.
        /// </summary>
        /// 
        /// <value>
        /// A Uri representing the URL to the open query including the query
        /// string parameters containing the ID of the open query.  
        /// This URL will not contain the pin code if one is required, 
        /// so it cannot be used to directly invoke pin protected queries.  
        /// </value>
        /// 
        /// <remarks>
        /// The URL for the open query is issued by the HealthVault 
        /// service when the open query is created.
        /// </remarks>
        /// 
        public Uri Url
        {
            get
            {
                if (_url == null)
                {
                    return CreateOpenQueryUrl(Id);
                }
                return _url;
            }
            set { _url = value; }
        }
        private Uri _url;

        /// <summary>
        /// Gets or sets the unique identifier for the <see cref="OpenQuery"/> instance.
        /// </summary>
        /// 
        /// <value>
        /// A GUID representing the unique identifier for the open query.
        /// </value>
        /// 
        /// <remarks>
        /// The unique identifier for the open query is issued when the open
        /// query is created by the HealthVault service. This ID 
        /// is used as a query string parameter to the URL to access the open query.
        /// </remarks>
        /// 
        public Guid Id
        {
            get { return _id; }
            set { _id = value; }
        }
        internal Guid _id = Guid.Empty;

        /// <summary>
        /// Gets or sets the note attached to the open query.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the note for the open query.
        /// This property returns <b>null</b> if no note was attached.
        /// </value>
        /// 
        public string Note
        {
            get { return _note; }
            set { _note = value; }
        }
        internal string _note;

        /// <summary>
        /// Gets or sets a value indicating whether a PIN (personal identification 
        /// number) is required.
        /// </summary>
        /// 
        /// <returns>
        /// <b>true</b> if a PIN is required; otherwise, <b>false</b>.
        /// </returns>
        /// 
        public bool PinRequired
        {
            get { return _pinRequired; }
            set { _pinRequired = value; }
        }
        internal bool _pinRequired;

        /// <summary>
        /// Gets or sets the expiration date for the open query.
        /// </summary>
        /// 
        /// <returns>
        /// A DateTime representing the expiration date.
        /// </returns>
        /// 
        public DateTime ExpiresDate
        {
            get { return _expiresDate; }
            set { _expiresDate = value; }
        }
        internal DateTime _expiresDate = DateTime.MaxValue;

        /// <summary>
        /// Gets or sets the creation date of the open query.
        /// </summary>
        /// 
        /// <returns>
        /// A DateTime representing the creation date.
        /// </returns>
        /// 
        public DateTime CreateDate
        {
            get { return _createDate; }
            set { _createDate = value; }
        }
        internal DateTime _createDate = DateTime.MinValue;

        /// <summary>
        /// Gets or sets the name of the application that created this open query.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the application name.
        /// </returns>
        /// 
        public string ApplicationName
        {
            get { return _appName; }
            set { _appName = value; }
        }
        internal string _appName = null;

        #endregion Public properties

        #region Public methods

        /// <summary>
        /// Invokes the open query with the specified timeout and returns the results.
        /// </summary>
        /// 
        /// <param name="defaultTimeout">
        /// The time in milliseconds before the invocation of the query will 
        /// timeout.
        /// </param>
        /// 
        /// <returns>
        /// A string representing the invocation results.
        /// </returns>
        /// 
        /// <remarks>
        /// The invocation results are returned as a string because
        /// any method can be called.
        /// An open query can be constructed as a call to any of the 
        /// HealthVault methods. You can also apply any transforms to the 
        /// method results as part of the open query. The returned string 
        /// contains the HTTP response. This could be the XML produced by the 
        /// HealthVault service method, or it can be a transformed version 
        /// of that XML data.
        /// </remarks>
        /// 
        /// <exception cref="InvalidOperationException">
        /// <cref name="PinRequired"/> is <b>true</b>, in which case you should  
        /// use the <cref name="Invoke(int,string)"/> method instead.
        /// </exception>
        /// 
        public string Invoke(int defaultTimeout)
        {
            Validator.ThrowInvalidIf(this.PinRequired, "PinCodeRequired");

            using (EasyWebRequest easyWeb = new EasyWebRequest())
            {
                easyWeb.TimeoutMilliseconds = defaultTimeout;
                easyWeb.Fetch(Url);
                return easyWeb.ResponseText;
            }
        }


        /// <summary>
        /// Invokes the open query with the specified timeout and personal 
        /// identification number (PIN) and returns the results.
        /// </summary>
        /// 
        /// <param name="defaultTimeout">
        /// The time in seconds before the invocation of the query will 
        /// timeout.
        /// </param>
        /// 
        /// <param name="pinCode">
        /// The  code required to access the query.
        /// </param>
        /// 
        /// <returns>
        /// A string representing the invocation results.
        /// </returns>
        /// 
        /// <remarks>
        /// The invocation results are returned as a string because
        /// any method can be called.
        /// An open query can be constructed as a call to any of the 
        /// HealthVault methods. You can also apply any transforms to the 
        /// method results as part of the open query. The returned string 
        /// contains the HTTP response. This could be the XML produced by the 
        /// HealthVault service method, or it can be a transformed version 
        /// of that XML data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="pinCode"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        public string Invoke(int defaultTimeout, string pinCode)
        {
            Validator.ThrowIfStringNullOrEmpty(pinCode, "pinCode");

            Uri requestUrl = CreateOpenQueryUrl(Id, pinCode);

            using (EasyWebRequest easyWeb = new EasyWebRequest())
            {
                easyWeb.TimeoutMilliseconds = defaultTimeout;
                easyWeb.Fetch(requestUrl);
                return easyWeb.ResponseText;
            }
        }

        /// <summary>
        /// Removes the saved open query from the server.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The connection instance to use to remove the <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <remarks>
        /// The person authenticated with the <paramref name="connection"/> 
        /// must have permission to remove the open query.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public void Remove(AuthenticatedConnection connection)
        {
            HealthVaultPlatform.RemoveOpenQuery(connection, Id);
        }

        /// <summary>
        /// Gets information about an open query.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The <see cref="AuthenticatedConnection"/> instance to use for 
        /// getting information about the open query.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public OpenQuery GetInfoFromOpenQuery(AuthenticatedConnection connection)
        {
            return GetInfoFromOpenQuery(connection, Id);
        }

        /// <summary>
        /// Gets a string representation of the open query URL.
        /// </summary>
        /// 
        /// <returns>
        /// The open query URL as a string;
        /// </returns>
        /// 
        /// <remarks>
        /// The open query URL is a URL to a HealthVault service page that 
        /// also has the query string parameter to identify which open query to 
        /// run.
        /// </remarks>
        /// 
        public override string ToString()
        {
            return this.Url.ToString();
        }
        #endregion Public methods

        #region Static methods

        /// <summary>
        /// Creates a new open query using the specified 
        /// <see cref="AuthenticatedConnection"/> and definition.
        /// </summary>
        /// 
        /// <param name="connection">
        /// An <see cref="AuthenticatedConnection"/> instance that creates the new open query.
        /// </param>
        /// 
        /// <param name="searcher">
        /// A <see cref="HealthRecordSearcher"/> instance that defines the open query.
        /// </param>
        /// 
        /// <returns>
        /// An <see cref="OpenQuery"/> instance that represents the newly created query.
        /// 
        /// </returns>
        /// 
        /// <remarks>
        /// The creation of an open query makes the data returned by that 
        /// query public. The only obscurity to the data is that the query
        /// URL must be known to retrieve it.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="searcher"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="searcher"/> parameter contains no valid
        /// search filters.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery NewQuery(
            AuthenticatedConnection connection,
            HealthRecordSearcher searcher)
        {
            return NewQuery(
                connection,
                searcher,
                Int32.MaxValue,
                String.Empty,
                String.Empty,
                null);
        }

        /// <summary>
        /// Creates a new open query using the specified 
        /// <see cref="OfflineWebApplicationConnection"/> and definition.
        /// </summary>
        /// 
        /// <param name="connection">
        /// An <see cref="OfflineWebApplicationConnection"/> instance that 
        /// creates the new open query.
        /// </param>
        /// 
        /// <param name="searcher">
        /// A <see cref="HealthRecordSearcher"/> instance that defines the open query.
        /// </param>
        /// 
        /// <returns>
        /// An <see cref="OpenQuery"/> instance that represents the newly created query.
        /// </returns>
        /// 
        /// <remarks>
        /// The creation of an open query makes public the data returned by that 
        /// query. However, the query URL must be known to retrieve the data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="searcher"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="searcher"/> parameter contains no valid
        /// search filters.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery NewQuery(
            OfflineWebApplicationConnection connection,
            HealthRecordSearcher searcher)
        {
            return NewQuery(
                connection,
                searcher,
                Int32.MaxValue,
                String.Empty,
                String.Empty,
                null);
        }

        /// <summary>
        /// Creates a new open query using the specified 
        /// <see cref="AuthenticatedConnection"/>, definition, and personal
        /// identification number (PIN).
        /// </summary>
        /// 
        /// <param name="connection">
        /// An <see cref="AuthenticatedConnection"/> instance that creates the 
        /// new open query.
        /// </param>
        /// 
        /// <param name="searcher">
        /// A <see cref="HealthRecordSearcher"/> instance that defines the open query.
        /// </param>
        /// 
        /// <param name="pinCode">
        /// The PIN that protects the query.  
        /// </param>
        /// 
        /// <returns>
        /// An <see cref="OpenQuery"/> instance that represents the newly created query.
        /// </returns>
        /// 
        /// <remarks>
        /// The creation of an open query makes public the data returned by that 
        /// query. However, the query URL must be known to retrieve the data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> or <paramref name="searcher"/> 
        /// parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="searcher"/> parameter contains no valid search
        /// filters or the <paramref name="pinCode"/> parameter is <b>null</b> 
        /// or empty.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery NewQuery(
            AuthenticatedConnection connection,
            HealthRecordSearcher searcher,
            string pinCode)
        {
            Validator.ThrowIfStringNullOrEmpty(pinCode, "pinCode");

            return NewQuery(
                connection,
                searcher,
                Int32.MaxValue,
                pinCode,
                String.Empty,
                null);
        }

        /// <summary>
        /// Creates a new open query using the specified 
        /// <see cref="OfflineWebApplicationConnection"/>, definition, and personal
        /// identification number (PIN).
        /// </summary>
        /// 
        /// <param name="connection">
        /// A connection instance that creates the new open query.
        /// </param>
        /// 
        /// <param name="searcher">
        /// A <see cref="HealthRecordSearcher"/> instance that defines the open query.
        /// </param>
        /// 
        /// <param name="pinCode">
        /// The PIN that protects the query.  
        /// </param>
        /// 
        /// <returns>
        /// An <see cref="OpenQuery"/> instance that represents the newly created query.
        /// </returns>
        /// 
        /// <remarks>
        /// The creation of an open query makes public the data returned by that 
        /// query. However, the query URL must be known to retrieve the data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> or <paramref name="searcher"/> 
        /// parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="searcher"/> parameter contains no valid search
        /// filters or the <paramref name="pinCode"/> parameter is <b>null</b> 
        /// or empty.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery NewQuery(
            OfflineWebApplicationConnection connection,
            HealthRecordSearcher searcher,
            string pinCode)
        {
            Validator.ThrowIfStringNullOrEmpty(pinCode, "pinCode");

            return NewQuery(
                connection,
                searcher,
                Int32.MaxValue,
                pinCode,
                String.Empty,
                null);
        }

        /// <summary>
        /// Creates a new open query using the specified 
        /// <see cref="AuthenticatedConnection"/>, definition, expiration time,
        /// personal identification number (PIN), description, and XSL.
        /// </summary>
        /// 
        /// <param name="connection">
        /// An <see cref="AuthenticatedConnection"/> instance that creates the 
        /// new open query.
        /// </param>
        /// 
        /// <param name="searcher">
        /// A <see cref="HealthRecordSearcher"/> instance that defines the open query.
        /// </param>
        ///
        /// <param name="expires">
        /// The number of minutes the query will expire from the creation time.
        /// A value of Int32.MaxValue denotes that the query does not expire.
        /// </param>
        ///
        /// <param name="pinCode">
        /// The PIN that protects the query.  
        /// </param>
        ///
        /// <param name="note">
        /// The note describing the query.
        /// </param>
        /// 
        /// <param name="finalXsl">
        /// The XSL that transforms the results of the query when the 
        /// <see cref="OpenQuery"/> is invoked.
        /// </param>
        /// 
        /// <returns>
        /// An <see cref="OpenQuery"/> instance that represents the newly created query.
        /// </returns>
        /// 
        /// <remarks>
        /// The creation of an open query makes public the data returned by that 
        /// query. However, the query URL must be known to retrieve the data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> or <paramref name="searcher"/> 
        /// parameter is <b>null</b>.
        /// </exception>
        /// 
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="searcher"/> parameter contains no valid search
        /// filters or the <paramref name="pinCode"/> parameter is <b>null</b> 
        /// or empty.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery NewQuery(
            AuthenticatedConnection connection,
            HealthRecordSearcher searcher,
            int expires,
            string pinCode,
            string note,
            string finalXsl)
        {
            return HealthVaultPlatform.NewOpenQuery(
                connection,
                searcher,
                expires,
                pinCode,
                note,
                finalXsl);
        }

        /// <summary>
        /// Creates a new open query using the specified 
        /// <see cref="OfflineWebApplicationConnection"/>, definition, 
        /// expiration time, personal identification number (PIN), description, 
        /// and XSL.
        /// </summary>
        /// 
        /// <param name="connection">
        /// An <see cref="OfflineWebApplicationConnection"/> instance that 
        /// creates the new open query.
        /// </param>
        /// 
        /// <param name="searcher">
        /// A <see cref="HealthRecordSearcher"/> instance that defines the open query.
        /// </param>
        ///
        /// <param name="expires">
        /// The number of minutes the query will expire from the creation time.
        /// A value of Int32.MaxValue denotes that the query does not expire.
        /// </param>
        ///
        /// <param name="pinCode">
        /// The PIN that protects the query.  
        /// </param>
        ///
        /// <param name="note">
        /// The note describing the query.
        /// </param>
        /// 
        /// <param name="finalXsl">
        /// The XSL that transforms the results of the query when the 
        /// <see cref="OpenQuery"/> is invoked.
        /// </param>
        /// 
        /// <returns>
        /// An <see cref="OpenQuery"/> instance that represents the newly created query.
        /// </returns>
        /// 
        /// <remarks>
        /// The creation of an open query makes public the data returned by that 
        /// query. However, the query URL must be known to retrieve the data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> or <paramref name="searcher"/> 
        /// parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="searcher"/> parameter contains no valid search
        /// filters or the <paramref name="pinCode"/> parameter is <b>null</b> 
        /// or empty.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery NewQuery(
            OfflineWebApplicationConnection connection,
            HealthRecordSearcher searcher,
            int expires,
            string pinCode,
            string note,
            string finalXsl)
        {
            return HealthVaultPlatform.NewOpenQuery(
                connection,
                searcher,
                expires,
                pinCode,
                note,
                finalXsl);
        }

        /// <summary>
        /// Invokes the open query given the specified timeout and URL and 
        /// returns the results.
        /// </summary>
        /// 
        /// <param name="defaultTimeout">
        /// The time in seconds before the invocation of the query will 
        /// timeout.
        /// </param>
        /// 
        /// <param name="requestUrl">
        /// A URI representing the complete URL of an existing <see cref="OpenQuery"/>.
        /// The URL must include the query ID and personal identification number
        /// (PIN) if required.
        /// </param>
        /// 
        /// <returns>
        /// A string representing the invocation results.
        /// </returns>
        /// 
        /// <remarks>
        /// The invocation results are returned as a string because
        /// any method can be called.
        /// An open query can be constructed as a call to any of the 
        /// HealthVault methods. You can also apply any transforms to the 
        /// method results as part of the open query. The returned string 
        /// contains the HTTP response. This could be the XML produced by the 
        /// HealthVault service method, or it can be a transformed version 
        /// of that XML data.
        /// </remarks>
        /// 
        public static string Invoke(int defaultTimeout, Uri requestUrl)
        {
            using (EasyWebRequest easyWeb = new EasyWebRequest())
            {
                easyWeb.TimeoutMilliseconds = defaultTimeout;
                easyWeb.Fetch(requestUrl);
                return easyWeb.ResponseText;
            }
        }

        /// <summary>
        /// Invokes the open query given the specified timeout and query ID 
        /// and returns the results.
        /// </summary>
        /// 
        /// <param name="defaultTimeout">
        /// The time in seconds before the invocation of the query will 
        /// timeout.
        /// </param>
        /// 
        /// <param name="queryId">
        /// The ID of an existing OpenQuery.
        /// </param>
        /// 
        /// <returns>
        /// A string representing the invocation results.
        /// </returns>
        /// 
        /// <remarks>
        /// The invocation results are returned as a string because
        /// any method can be called.
        /// An open query can be constructed as a call to any of the 
        /// HealthVault methods. You can also apply any transforms to the 
        /// method results as part of the open query. The returned string 
        /// contains the HTTP response. This could be the XML produced by the 
        /// HealthVault service method, or it can be a transformed version 
        /// of that XML data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="queryId"/> parameter is empty.
        /// </exception>
        /// 
        public static string Invoke(int defaultTimeout, Guid queryId)
        {
            Validator.ThrowArgumentExceptionIf(
                queryId == Guid.Empty,
                "queryId",
                "QueryIdInvalid");

            Uri requestUrl = CreateOpenQueryUrl(queryId);

            return Invoke(
                defaultTimeout,
                requestUrl);
        }

        /// <summary>
        /// Invokes the open query given the specified timeout, query ID, and 
        /// personal identification number (PIN).
        /// </summary>
        /// 
        /// <param name="defaultTimeout">
        /// The time in seconds before the invocation of the query will 
        /// timeout.
        /// </param>
        /// 
        /// <param name="queryId">
        /// The ID of an existing <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <param name="pinCode">
        /// The PIN that is required to access the query.
        /// </param>
        /// 
        /// <returns>
        /// A string representing the invocation results.
        /// </returns>
        /// 
        /// <remarks>
        /// The invocation results are returned as a string because
        /// any method can be called.
        /// An open query can be constructed as a call to any of the 
        /// HealthVault methods. You can also apply any transforms to the 
        /// method results as part of the open query. The returned string 
        /// contains the HTTP response. This could be the XML produced by the 
        /// HealthVault service method, or it can be a transformed version 
        /// of that XML data.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="queryId"/> parameter is empty.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="pinCode"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        public static string Invoke(
            int defaultTimeout,
            Guid queryId,
            string pinCode)
        {
            Validator.ThrowArgumentExceptionIf(
                queryId == Guid.Empty,
                "queryId",
                "QueryIdInvalid");

            Validator.ThrowIfStringNullOrEmpty(pinCode, "pinCode");

            Uri requestUrl = CreateOpenQueryUrl(queryId, pinCode);

            return Invoke(defaultTimeout, requestUrl);
        }

        /// <summary>
        /// Removes the saved open query from the server.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The <see cref="AuthenticatedConnection"/> instance used to remove 
        /// the <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <param name="queryId">
        /// The unique identifier of the open query that will be removed.
        /// </param>
        /// 
        /// <remarks>
        /// The person authenticated with the <paramref name="connection"/> 
        /// must have permission to remove the open query.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="queryId"/> parameter is empty.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static void Remove(
            AuthenticatedConnection connection,
            Guid queryId)
        {
            HealthVaultPlatform.RemoveOpenQuery(connection, queryId);
        }

        /// <summary>
        /// Gets information about an open query.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The <see cref="AuthenticatedConnection"/> instance used to
        /// get information about the open query.
        /// </param>
        /// 
        /// <param name="queryId">
        /// The unique identifier of the open query for which the information 
        /// will be retrieved.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="queryId"/> parameter is empty.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthServiceException">
        /// An error occurred when HealthVault processed the request.
        /// </exception>
        /// 
        public static OpenQuery GetInfoFromOpenQuery(
            AuthenticatedConnection connection,
            Guid queryId)
        {
            return HealthVaultPlatform.GetInfoFromOpenQuery(connection, queryId);
        }

        #endregion Static methods

        #region helpers

        private static Uri CreateOpenQueryUrl(
            Guid queryId,
            string pinCode)
        {
            string queryUrl =
                HealthApplicationConfiguration.Current.HealthVaultOpenQueryRequestUrl
                + "?id="
                + queryId.ToString();

            if (!String.IsNullOrEmpty(pinCode))
            {
                queryUrl += "&pin=" + pinCode;
            }

            return new Uri(queryUrl, UriKind.Absolute);
        }

        private static Uri CreateOpenQueryUrl(
            Guid queryId)
        {
            return CreateOpenQueryUrl(
                queryId,
                String.Empty);
        }

        #endregion helpers
    }
}


