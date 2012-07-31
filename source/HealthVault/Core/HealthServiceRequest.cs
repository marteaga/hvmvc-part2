// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Health.Authentication;
using System.Web;
using Microsoft.Health.Web;

namespace Microsoft.Health
{

    /// <summary>
    /// Represents an individual request to a HealthVault service.
    /// The class wraps up the XML generation and web request/response.
    /// </summary>
    /// 
    /// <remarks>
    /// An instance of this class can be retrieved by calling the 
    /// <see cref="Microsoft.Health.HealthServiceConnection.CreateRequest(string, int)"/> 
    /// method.
    /// This class is not thread safe. A new instance should be created when multiple requests 
    /// must execute concurrently.
    /// </remarks>
    /// 
    public class HealthServiceRequest : IEasyWebResponseHandler
    {
        /// <summary>
        /// Creates a new instance of the <see cref="HealthServiceRequest"/> 
        /// class for the specified method.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The client-side representation of the HealthVault service.
        /// </param>
        /// 
        /// <param name="methodName">
        /// The name of the method to invoke on the service.
        /// </param>
        /// 
        /// <param name="methodVersion">
        /// The version of the method to invoke on the service.
        /// </param>
        ///
        /// <param name="record">
        /// The record to use.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="methodName"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        public HealthServiceRequest(
            HealthServiceConnection connection,
            string methodName,
            int methodVersion,
            HealthRecordAccessor record) :
            this(connection, methodName, methodVersion)
        {
            _recordId = record.Id;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="HealthServiceRequest"/> 
        /// class for the specified method.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The client-side representation of the HealthVault service.
        /// </param>
        /// 
        /// <param name="methodName">
        /// The name of the method to invoke on the service.
        /// </param>
        /// 
        /// <param name="methodVersion">
        /// The version of the method to invoke on the service.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="methodName"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        public HealthServiceRequest(
            HealthServiceConnection connection,
            string methodName, 
            int methodVersion)
        {
            Validator.ThrowIfArgumentNull(connection, "connection", "CtorServiceNull");
            Validator.ThrowIfStringNullOrEmpty(methodName, "methodName");

            _connection = connection;
            AuthenticatedConnection authenticatedConnection = connection as AuthenticatedConnection;
            if (authenticatedConnection != null)
            {
                ImpersonatedPersonId = authenticatedConnection.ImpersonatedPersonId;
            }

            List<HealthServiceRequest> pendingRequests = connection.PendingRequests;

            lock (pendingRequests)
            {
                connection.PendingRequests.Add(this);
            }

            _methodName = methodName;
            _timeoutSeconds = connection.RequestTimeoutSeconds;
            _msgTimeToLive = connection.RequestTimeToLive;
            _language = connection.Culture.TwoLetterISOLanguageName;

            string[] langAndCountry = connection.Culture.Name.Split('-');
            if (langAndCountry.Length > 1)
            {
                _country = langAndCountry[1];
            }

            _methodVersion = methodVersion;
        }

        /// <summary>
        /// Builds up the XML, makes the request and reads the response.
        /// Connectivity failures will except out of the http client
        /// </summary>
        /// 
        /// <exception cref ="HealthServiceException">
        /// The HealthVault returns an exception in the form of an 
        /// exception section in the response XML.
        /// </exception>
        /// 
        public virtual void Execute()
        {
            if (_connection.Credential != null)
            {
                _connection.Credential.AuthenticateIfRequired(_connection, _connection.ApplicationId);
            }

            try
            {
                ExecuteInternal();
            }
            catch (HealthServiceAuthenticatedSessionTokenExpiredException)
            {
                if (_connection.Credential != null)
                {
                    // Mark the credential's authentication result as expired,
                    // so that in the following 
                    // Credential.AuthenticateIfRequired we fetch a new token.
                    if (_connection.Credential.ExpireAuthenticationResult(_connection.ApplicationId))
                    {
                        _connection.Credential.AuthenticateIfRequired(_connection, _connection.ApplicationId);

                        ExecuteInternal();
                        return;
                    }
                }

                throw;
            }
        }

        internal virtual void ExecuteInternal()
        {
            try
            {
                _currentEasyWeb = this.BuildWebRequest(null);
                _currentEasyWeb.RequestCompressionMethod = RequestCompressionMethod;

                _currentEasyWeb.Fetch(_connection.RequestUrl, this);
            }
            catch (XmlException xmlException)
            {
                throw new HealthServiceException(
                    ResourceRetriever.GetResourceString("InvalidResponseFromXMLRequest"),
                    xmlException);
            }
            finally
            {
                if (_currentEasyWeb != null)
                {
                    _currentEasyWeb.Dispose();
                    _currentEasyWeb = null;
                }

                List<HealthServiceRequest> pendingRequests = _connection.PendingRequests;
                lock (pendingRequests)
                {
                    _connection.PendingRequests.Remove(this);
                }
            }
        }

        /// <summary>
        /// Cancels any pending request to HealthVault that was initiated with the same connection
        /// as this request.
        /// </summary>
        /// 
        /// <remarks>
        /// Calling this method will cancel any requests that was started using the connection.
        /// It is up to the caller to start the request on another thread. Cancelling will cause
        /// a HealthServiceRequestCancelledException to be thrown on the thread the request was
        /// executed on.
        /// </remarks>
        /// 
        public void CancelRequest()
        {
            if (_currentEasyWeb != null)
            {
                _currentEasyWeb.CancelRequest();
            }
            else
            {
                _pendingCancel = true;
            }
        }

        /// <summary>
        /// Same as Execute, but takes a transform url (or tag) that is
        /// used to transform the result (on the server). Since the
        /// response is no longer necessarily xml, it is returned as
        /// a string
        /// </summary>
        /// 
        /// <param name="transform">
        /// The public URL of the transform to apply to the results. If <b>null</b>,
        /// no transform is applied and the results are returned
        /// as a string.
        /// </param>
        /// 
        public virtual string ExecuteForTransform(string transform)
        {
            if (_connection.Credential != null)
            {
                _connection.Credential.AuthenticateIfRequired(_connection, _connection.ApplicationId);
            }

            try
            {
                return ExecuteForTransformInternal(transform);
            }
            catch (HealthServiceAuthenticatedSessionTokenExpiredException)
            {
                if (_connection.Credential != null)
                {
                    // Mark the credential's authentication result as expired,
                    // so that in the following 
                    // Credential.AuthenticateIfRequired we fetch a new token.
                    if (_connection.Credential.ExpireAuthenticationResult(_connection.ApplicationId))
                    {
                        _connection.Credential.AuthenticateIfRequired(_connection, _connection.ApplicationId);

                        return ExecuteForTransformInternal(transform);
                    }
                }

                throw;
            }
        }

        internal virtual string ExecuteForTransformInternal(string transform)
        {
            String result = null;
            try
            {
                _currentEasyWeb = this.BuildWebRequest(transform);
                _currentEasyWeb.RequestCompressionMethod = RequestCompressionMethod;
                _currentEasyWeb.Fetch(_connection.RequestUrl);

                result = _currentEasyWeb.ResponseText;
            }
            finally
            {
                if (_currentEasyWeb != null)
                {
                    _currentEasyWeb.Dispose();
                    _currentEasyWeb = null;
                }

                List<HealthServiceRequest> pendingRequests = _connection.PendingRequests;
                lock (pendingRequests)
                {
                    _connection.PendingRequests.Remove(this);
                }
            }

            // Now look at the errors in the response before returning. If we see HV XML returned 
            // containing a failure status code, throw an exception

            if (HealthVaultPlatformTrace.LoggingEnabled)
            {
                HealthVaultPlatformTrace.LogResponse(result);
            }

            XmlReaderSettings settings = SDKHelper.XmlReaderSettings;
            settings.CloseInput = false;
            settings.IgnoreWhitespace = false;

            try
            {
                using (XmlReader reader = XmlReader.Create(new StringReader(result), settings))
                {
                    reader.NameTable.Add("wc");

                    if (SDKHelper.ReadUntil(reader, "response"))
                    {
                        if (SDKHelper.ReadUntil(reader, "status"))
                        {
                            if (SDKHelper.ReadUntil(reader, "code"))
                            {
                                int responseCode = reader.ReadElementContentAsInt();

                                HealthServiceStatusCode errorCode =
                                    HealthServiceStatusCodeManager.GetStatusCode(responseCode);

                                if (errorCode != HealthServiceStatusCode.Ok)
                                {
                                    HealthServiceResponseError error = HandleErrorResponse(reader);

                                    HealthServiceException e =
                                        HealthServiceExceptionHelper.GetHealthServiceException(
                                            responseCode,
                                            error);

                                    throw e;
                                }
                            }
                        }
                    }
                }
            }
            catch (FormatException)
            {
            }
            catch (MissingFieldException)
            {
            }
            catch (XmlException)
            {
            }
            catch (InvalidOperationException)
            {
            }
            return result;
        }

        #region helpers

        /// <summary>
        /// Creates a Web request that can be sent to HealthVault.
        /// </summary>
        /// 
        /// <param name="transform">
        /// The optional XSL to apply.
        /// </param>
        /// 
        /// <returns>
        /// An instance of <see cref="EasyWebRequest"/>.
        /// </returns>
        /// 
        private EasyWebRequest BuildWebRequest(string transform)
        {
            if (_pendingCancel || _connection.CancelAllRequests)
            {
                _pendingCancel = false;
                throw new HealthServiceRequestCancelledException();
            }

            this.BuildRequestXml(transform);

            HealthVaultPlatformTrace.LogRequest(_xmlRequest);

            EasyWebRequest easyWeb = EasyWebRequest.Create(_xmlRequest, _xmlRequestLength);
            easyWeb.WebProxy = _connection.WebProxy;
            easyWeb.TimeoutMilliseconds = (_timeoutSeconds * 1000);
            easyWeb.RequestCompressionMethod = RequestCompressionMethod;

            return easyWeb;
        }

        /// <summary>
        /// Connects the XML using default values. 
        /// </summary>
        ///
        /// <exception cref="XmlException">
        /// There is a failure building up the XML.
        /// </exception>
        /// 
        /// <private>
        /// This is protected so that the derived testing class can call it
        /// to create the request XML and then verify it is correct.
        /// </private>
        /// 
        protected void BuildRequestXml()
        {
            BuildRequestXml(null);
        }

        /// <summary>
        /// Gets or sets the request compression method used by the connection.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the request compression method.
        /// </returns>
        /// 
        public string RequestCompressionMethod
        {
            get { return _connection.RequestCompressionMethod; }
            set { _connection.RequestCompressionMethod = value; }
        }

        /// <summary>
        /// Connects the XML using the specified optional XSL. 
        /// </summary>
        /// <param name="transform">The optional XSL to apply.</param> 
        ///
        /// <exception cref="XmlException">
        /// There is a failure building up the XML.
        /// </exception>
        /// 
        /// <private>
        /// This is protected so that the derived testing class can call it
        /// to create the request XML and then verify it is correct.
        /// </private>
        /// 
        protected void BuildRequestXml(string transform)
        {
            // first, construct the non-authenticated sections sequentially
            string infoHash;
            Byte[] infoXml;
            int infoXmlLength;
            Byte[] headerXml;
            int headerXmlLength;
            MemoryStream requestXml = null;
            XmlWriter writer = null;

            GetInfoSection(out infoHash, out infoXml, out infoXmlLength);
            GetHeaderSection(transform, infoHash, out headerXml, out headerXmlLength);
            try
            {
                requestXml = new MemoryStream(infoXml.Length + headerXml.Length + 512);
                XmlWriterSettings settings = SDKHelper.XmlUtf8WriterSettings;

                writer = XmlWriter.Create(requestXml, settings);

                // now, construct the final xml sequentially

                // <request>
                writer.WriteStartElement("wc-request", "request", "urn:com.microsoft.wc.request");

                // <auth>
                // If we have an authenticated section, then construct the auth data otherwise do 
                // not include an auth section.
                if (_connection.Credential != null)
                {
                    string authInnerXml = _connection.Credential.AuthenticateData(headerXml, 0, headerXmlLength);

                    if (!String.IsNullOrEmpty(authInnerXml))
                    {
                        writer.WriteStartElement("auth");
                        writer.WriteRaw(authInnerXml);
                        writer.WriteEndElement();
                    }
                }

                writer.WriteRaw(Encoding.UTF8.GetString(headerXml, 0, headerXmlLength));
                writer.WriteRaw(Encoding.UTF8.GetString(infoXml, 0, infoXmlLength));

                // </request>
                writer.WriteEndElement();

                writer.Flush();

                // MemoryStream.Flush() does nothing, don't call
                _xmlRequest = requestXml.GetBuffer();
                _xmlRequestLength = (int)requestXml.Length;
            }
            finally
            {
                if (writer != null)
                {
                    writer.Close();
                    ((IDisposable)writer).Dispose();
                    writer = null;
                }
            }
        }

        private void GetInfoSection(
            out string infoHash, 
            out Byte[] infoSection, 
            out int infoSectionLength)
        {
            XmlWriterSettings settings = SDKHelper.XmlUtf8WriterSettings;

            MemoryStream infoXml = null;
            XmlWriter writer = null;
            try
            {
                infoXml = new MemoryStream(Parameters.Length + 16);
                writer = XmlWriter.Create(infoXml, settings);

                writer.WriteStartElement("info");
                writer.WriteRaw(Parameters);
                writer.WriteEndElement();
                writer.Flush();

                infoSection = infoXml.GetBuffer();
                infoSectionLength = (int)infoXml.Length;

                // if we are not using an auth connection,
                // then there is no point in hashing the info section
                // because we cannot protect the resulting hash
                infoHash = 
                    _connection.Credential != null
                         ? CryptoHash.CreateInfoHash(infoSection, 0, infoSectionLength)
                         : String.Empty;
            }
            finally
            {
                if (writer != null)
                {
                    writer.Close();
                    ((IDisposable)writer).Dispose();
                    writer = null;
                }
            }
        }

        private void GetHeaderSection(
            string transform,
            string infoHash,
            out Byte[] headerXml,
            out int headerXmlLength)
        {
            XmlWriterSettings settings = SDKHelper.XmlUtf8WriterSettings;

            MemoryStream xmlHeader = null;
            XmlWriter writer = null;

            try
            {
                xmlHeader = new MemoryStream(2048);
                writer = XmlWriter.Create(xmlHeader, settings);

                // <header>
                writer.WriteStartElement("header");

                // <method>
                writer.WriteElementString("method", _methodName);

                if (_methodVersion != null)
                {
                    // <method-version>
                    writer.WriteElementString("method-version", _methodVersion.Value.ToString());
                }

                if (_targetPersonId != Guid.Empty)
                {
                    // <target-person-id>
                    writer.WriteElementString("target-person-id", _targetPersonId.ToString());
                }

                if (_recordId != Guid.Empty)
                {
                    // <record-id>
                    writer.WriteElementString("record-id", _recordId.ToString());
                }

                    // header based on the kind of connection we have...

                if (_connection.Credential != null &&
                    !String.IsNullOrEmpty(_connection.AuthenticationToken))
                {
                    writer.WriteStartElement("auth-session");

                    _connection.Credential.GetHeaderSection(_connection.ApplicationId, writer);

                    OfflineWebApplicationConnection offlineConnection = _connection as OfflineWebApplicationConnection;
                    if (offlineConnection != null)
                    {
                        if (offlineConnection.OfflinePersonId != Guid.Empty)
                        {
                            // person-specific request, but person is offline as far as
                            // HealthVault is concerned, so pass in offline info...
                            // <offline-person-info>
                            writer.WriteStartElement("offline-person-info");

                            // <offline-person-id>
                            writer.WriteElementString(
                                "offline-person-id",
                                offlineConnection.OfflinePersonId.ToString());

                            // </offline-person-info>
                            writer.WriteEndElement();
                        }
                    }

                    writer.WriteEndElement();
                }
                else
                {
                    writer.WriteElementString("app-id", _connection.ApplicationId.ToString());
                }

                if (_language != null)
                {
                    writer.WriteElementString("language", _language);
                }

                if (_country != null)
                {
                    writer.WriteElementString("country", _country);
                }


                if (transform != null)
                {
                    writer.WriteElementString("final-xsl", transform);
                }

                writer.WriteElementString("msg-time", SDKHelper.XmlFromNow());
                writer.WriteElementString(
                    "msg-ttl", _msgTimeToLive.ToString(CultureInfo.InvariantCulture));

                writer.WriteElementString("version", _version);

                // if we are not using an authenticated connection,
                // then do not include the info-hash because we cannot protect it
                //      with the auth section.
                if (_connection.Credential != null)
                {
                    writer.WriteStartElement("info-hash");
                    writer.WriteRaw(infoHash);
                    writer.WriteEndElement();
                }

                // </header>
                writer.WriteEndElement();

                writer.Flush();

                headerXml = xmlHeader.GetBuffer();
                headerXmlLength = (int)xmlHeader.Length;
            }
            finally
            {
                if (writer != null)
                {
                    writer.Close();
                    ((IDisposable)writer).Dispose();
                    writer = null;
                }
            }
        }

        /// <summary> 
        /// Represents the <see cref="IEasyWebResponseHandler"/> callback.
        /// </summary>
        /// 
        /// <param name="stream">
        /// The response stream.
        /// </param>
        /// 
        /// <exception cref ="HealthServiceException">
        /// HealthVault returns an exception in the form of an 
        /// exception section in the response XML.
        /// </exception>
        /// 
        public void HandleResponseStream(Stream stream)
        {
            if (_responseStreamHandler != null)
            {
                _responseStreamHandler(stream);
            }
            else
            {
                _response = HandleResponseStreamResult(stream);
            }
        }

        /// <summary>
        /// Defines a delegate for handling the response stream for a request.
        /// </summary>
        /// 
        /// <param name="stream">
        /// The response stream of the request.
        /// </param>
        /// 
        public delegate void WebResponseStreamHandler(Stream stream);

        /// <summary>
        /// Defines a delegate that gets or sets all responses for requests to the 
        /// HealthVault Service.
        /// </summary>
        /// 
        /// <remarks>
        /// If this property is set, the specified method is called once
        /// the response stream is retrieved for handling the result of the
        /// request to the HealthVault Service. If the property is not
        /// set, the response is processed and the results can be 
        /// retrieved using the <see cref="Response"/> property.
        /// </remarks>
        /// 
        public WebResponseStreamHandler ResponseStreamHandler
        {
            get { return _responseStreamHandler; }
            set { _responseStreamHandler = value; }
        }
        private WebResponseStreamHandler _responseStreamHandler;

        /// <summary>
        /// Handles the data retrieved by making the web request.
        /// </summary>
        /// 
        /// <param name="stream">
        /// The response stream from the web request.
        /// </param>
        /// 
        /// <exception cref ="HealthServiceException">
        /// HealthVault returns an exception in the form of an 
        /// exception section in the response XML.
        /// </exception>
        /// 
        public static HealthServiceResponseData HandleResponseStreamResult(
            Stream stream)
        {
            HealthServiceResponseData result = new HealthServiceResponseData();
            MemoryStream responseStream = stream as MemoryStream;

            if (responseStream == null)
            {
                try
                {
                    responseStream = new MemoryStream();
                    int count;
                    Byte[] buff = new Byte[1024 * 2];
                    while ((count = stream.Read(buff, 0, buff.Length)) > 0)
                    {
                        responseStream.Write(buff, 0, count);
                    }
                    responseStream.Flush();
                }
                finally
                {
                    stream.Close();
                    stream = null;
                }
            }
            if (HealthVaultPlatformTrace.LoggingEnabled)
            {
                HealthVaultPlatformTrace.LogResponse(
                    Encoding.UTF8.GetString(responseStream.GetBuffer(),
                    0,
                    (int)responseStream.Length));
            }

            XmlReaderSettings settings = SDKHelper.XmlReaderSettings;
            settings.CloseInput = false;
            settings.IgnoreWhitespace = false;
            responseStream.Position = 0;
            XmlReader reader = XmlReader.Create(responseStream, settings);
            reader.NameTable.Add("wc");

            if (!SDKHelper.ReadUntil(reader, "code"))
                throw new MissingFieldException("response", "code");

            result.CodeId = reader.ReadElementContentAsInt();

            if (result.Code == HealthServiceStatusCode.Ok)
            {
                if (reader.ReadToFollowing("wc:info"))
                {
                    result.InfoReader = reader;

                    byte[] buff = responseStream.GetBuffer();
                    int offset = 0;
                    int count = (int)responseStream.Length;

                    while (offset < count && buff[offset] != '<')
                    {
                        offset++;
                    }

                    result.ResponseText = new ArraySegment<Byte>(buff, offset, count - offset);
                }
                return result;
            }
            result.Error = HandleErrorResponse(reader);

            HealthServiceException e =
                HealthServiceExceptionHelper.GetHealthServiceException(result.CodeId, result.Error);

            throw e;

        }

        private static HealthServiceResponseError HandleErrorResponse(XmlReader reader)
        {
            HealthServiceResponseError error = new HealthServiceResponseError();

            // <error>
            if (String.Equals(reader.Name, "error", StringComparison.Ordinal))
            {
                // <message>
                if (!SDKHelper.ReadUntil(reader, "message"))
                {
                    throw new MissingFieldException("response", "message");
                }
                error.Message = reader.ReadElementString();

                // <context>
                SDKHelper.SkipToElement(reader);
                if (String.Equals(reader.Name, "context", StringComparison.Ordinal))
                {
                    HealthServiceErrorContext errorContext = new HealthServiceErrorContext();

                    // <server-name>
                    if (SDKHelper.ReadUntil(reader, "server-name"))
                    {
                        errorContext.ServerName = reader.ReadElementString();
                    }
                    else
                    {
                        throw new MissingFieldException("context", "server-name");
                    }

                    // <server-ip>
                    Collection<IPAddress> ipAddresses = new Collection<IPAddress>();

                    SDKHelper.SkipToElement(reader);
                    while (reader.Name.Equals("server-ip", StringComparison.Ordinal))
                    {
                        string ipAddressString = reader.ReadElementString();
                        IPAddress ipAddress = null;
                        if (IPAddress.TryParse(ipAddressString, out ipAddress))
                        {
                            ipAddresses.Add(ipAddress);
                        }
                        SDKHelper.SkipToElement(reader);
                    }
                    errorContext.SetServerIpAddresses(ipAddresses);

                    // <exception>
                    if (reader.Name.Equals("exception", StringComparison.Ordinal))
                    {
                        errorContext.InnerException = reader.ReadElementString();
                        SDKHelper.SkipToElement(reader);
                    }
                    else
                    {
                        throw new MissingFieldException("context", "exception");
                    }
                    error.Context = errorContext;
                }

                // <error-info>
                if (SDKHelper.ReadUntil(reader, "error-info"))
                {
                    error.ErrorInfo = reader.ReadElementString();
                    SDKHelper.SkipToElement(reader);
                }

            }
            return error;
        }

        #endregion

        #region properties

        /// <summary>
        /// Gets or sets the method name to call.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the method name.
        /// </returns>
        /// 
        public string MethodName
        {
            get { return _methodName; }
            set { _methodName = value; }
        }
        private string _methodName;

        /// <summary>
        /// Gets or sets the version of the method to call.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the version.
        /// </returns>
        /// 
        /// <remarks>
        /// If <b>null</b>, the current version is called.
        /// </remarks>
        /// 
        public int? MethodVersion
        {
            get { return _methodVersion; }
            set { _methodVersion = value; }
        }
        private int? _methodVersion;

        /// <summary>
        /// Gets or sets the identifier of the person being impersonated.
        /// </summary>
        /// 
        /// <returns>
        /// A GUID representing the identifier.
        /// </returns>
        /// 
        public Guid ImpersonatedPersonId
        {
            get { return _targetPersonId; }
            set { _targetPersonId = value; }
        }
        private Guid _targetPersonId = Guid.Empty;

        /// <summary>
        /// Gets or sets the record identifier.
        /// </summary>
        /// 
        /// <returns>
        /// A GUID representing the identifier.
        /// </returns>
        /// 
        public Guid RecordId
        {
            get { return _recordId; }
            set { _recordId = value; }
        }
        private Guid _recordId;

        /// <summary>
        /// Gets or sets the language for the request.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the language.
        /// </returns>
        /// 
        public string Language
        {
            get { return _language; }
            set { _language = value; }
        }
        private string _language;

        /// <summary>
        /// Gets or sets the country for the request.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the country.
        /// </returns>
        /// 
        public string Country
        {
            get { return _country; }
            set { _country = value; }
        }
        private string _country;

        private static string _version =
            typeof(HealthServiceRequest).Assembly.GetName().Version.ToString();

        /// <summary>
        /// Gets the HealthVault version for which this SDK was built.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the version.
        /// </returns>
        /// 
        internal static string Version
        {
            get { return _version; }
        }

        private string _parameters = String.Empty;

        /// <summary>
        /// Gets or sets the parameters for the method invocation.
        /// The parameters are specified via XML for the particular method.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the parameters.
        /// </returns>
        /// 
        public string Parameters
        {
            get
            {
                // We can't return null - we use the return value for setting
                // xml element's innter text - we'd have to do the value check
                // in several places in the code...
                if (_parameters == null)
                {
                    _parameters = String.Empty;
                }

                return _parameters;
            }
            set
            {
                _parameters = value;
            }
        }

        private int _timeoutSeconds;

        /// <summary>
        /// Gets or sets the timeout for the request, in seconds.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the timeout, in seconds.
        /// </returns>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The timeout value is set to less than 0.
        /// </exception>
        /// 
        public int TimeoutSeconds
        {
            get { return _timeoutSeconds; }
            set
            {
                Validator.ThrowArgumentOutOfRangeIf(
                    value < 0,
                    "TimeoutSeconds",
                    "TimeoutMustBePositive");

                _timeoutSeconds = value;
            }
        }

        /// <summary>
        /// Gets the response after Execute is called.
        /// </summary>
        /// 
        /// <returns>
        /// An instance of <see cref="HealthServiceResponseData"/>.
        /// </returns>
        /// 
        /// <private>
        /// The setter is internal as a test hook so that the response can 
        /// be set by test code in derived classes.
        /// </private>
        /// 
        public HealthServiceResponseData Response
        {
            get { return _response; }
            internal set { _response = value; }
        }

        #endregion

        /// <summary>
        /// This is a test hook so that testing class can set different time 
        /// to live to verify if HealthVault checks for it.
        /// </summary>
        /// 
        internal int TimeToLiveSeconds
        {
            get
            {
                return _msgTimeToLive;
            }
            set
            {
                _msgTimeToLive = value;
            }
        }
        private int _msgTimeToLive = 300;

        /// <summary>
        /// This is a test hook so that the derived testing class can
        /// verify the XML request.
        /// </summary>
        /// 
        internal Byte[] XmlRequest
        {
            get { return _xmlRequest; }
        }
        private Byte[] _xmlRequest;

        internal int XmlRequestLength
        {
            get { return _xmlRequestLength; }
        }
        private int _xmlRequestLength;

        private EasyWebRequest _currentEasyWeb;
        private bool _pendingCancel;
        private HealthServiceConnection _connection;
        private HealthServiceResponseData _response;
    }
}
