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
using System.Security;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Health.Authentication;

namespace Microsoft.Health.PlatformPrimitives
{

    /// <summary>
    /// Provides low-level access to the HealthVault open query operations.
    /// </summary>
    /// <remarks>
    /// <see cref="HealthVaultPlatform"/> uses this class to perform operations. Set 
    /// HealthVaultPlatformOpenQuery.Current to a derived class to intercept all message calls.
    /// </remarks>

    public class HealthVaultPlatformOpenQuery
    {
        /// <summary>
        /// Enables mocking of calls to this class.
        /// </summary>
        /// 
        /// <remarks>
        /// The calling class should pass in a class that derives from this
        /// class and overrides the calls to be mocked. 
        /// </remarks>
        /// 
        /// <param name="mock">The mocking class.</param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// There is already a mock registered for this class.
        /// </exception>
        /// 
        public static void EnableMock(HealthVaultPlatformOpenQuery mock)
        {
            Validator.ThrowInvalidIf(_saved != null, "ClassAlreadyMocked");

            _saved = _current;
            _current = mock;
        }

        /// <summary>
        /// Removes mocking of calls to this class.
        /// </summary>
        /// 
        /// <exception cref="InvalidOperationException">
        /// There is no mock registered for this class.
        /// </exception>
        /// 
        public static void DisableMock()
        {
            Validator.ThrowInvalidIfNull(_saved, "ClassIsntMocked");

            _current = _saved;
            _saved = null;
        }
        internal static HealthVaultPlatformOpenQuery Current
        {
            get { return _current; }
        }
        private static HealthVaultPlatformOpenQuery _current = new HealthVaultPlatformOpenQuery();
        private static HealthVaultPlatformOpenQuery _saved;


        /// <summary>
        /// Removes the saved open query from the server.
        /// </summary>
        /// 
        /// <param name="connection">
        /// The connection instance to use to remove the <see cref="OpenQuery"/>.
        /// </param>
        /// 
        /// <param name="id">
        /// The id of the open query to remove.
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
        public virtual void RemoveOpenQuery(
            ApplicationConnection connection,
            Guid id)
        {
            Validator.ThrowIfArgumentNull(connection, "connection", "NewQueryNullService");
            Validator.ThrowArgumentExceptionIf(
                id == Guid.Empty,
                "id",
                "QueryIdInvalid");

            HealthServiceRequest request =
                new HealthServiceRequest(connection, "DeleteOpenQuery", 1);

            request.Parameters = "<query-id>" + id.ToString() + "</query-id>";
            request.Execute();
        }

        /// <summary>
        /// Creates a new open query using the specified 
        /// connection, definition, expiration time,
        /// personal identification number (PIN), description, and XSL.
        /// </summary>
        /// 
        /// <param name="connection">
        /// A <see cref="ApplicationConnection"/> instance that creates the 
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
        public virtual OpenQuery NewOpenQuery(
            ApplicationConnection connection,
            HealthRecordSearcher searcher,
            int expires,
            string pinCode,
            string note,
            string finalXsl)
        {
            Validator.ThrowIfArgumentNull(connection, "connection", "NewQueryNullService");
            Validator.ThrowIfArgumentNull(searcher, "searcher", "NewQueryNullSearcher");

            Validator.ThrowArgumentExceptionIf(
                searcher.Filters == null ||
                searcher.Filters.Count == 0,
                "searcher.Filters",
                "NewQuerySearcherNoFilters");

            HealthServiceRequest request =
                new HealthServiceRequest(connection, "SaveOpenQuery", 1, searcher.Record);

            request.Parameters =
                GetSaveOpenQueryParameters(
                    searcher,
                    expires,
                    pinCode,
                    note,
                    finalXsl);
            request.Execute();

            return
                CreateOpenQueryFromSaveOpenQueryResponse(
                    request.Response.InfoNavigator);
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
        public virtual OpenQuery GetInfoFromOpenQuery(
            AuthenticatedConnection connection,
            Guid queryId)
        {
            Validator.ThrowIfArgumentNull(connection, "connection", "NewQueryNullService");

            Validator.ThrowArgumentExceptionIf(
                queryId == Guid.Empty,
                "queryId",
                "QueryIdInvalid");

            HealthServiceRequest request =
                new HealthServiceRequest(connection, "GetOpenQueryInfo", 1);

            request.Parameters = "<query-id>" + queryId.ToString() + "</query-id>";
            request.Execute();

            return
                CreateOpenQueryFromGetInfoResponse(
                    request.Response.InfoNavigator);
        }

        private static XPathExpression _infoQueryIdPath =
            XPathExpression.Compile("/wc:info");

        private static XPathExpression GetInfoQueryIdXPathExpression(
            XPathNavigator infoNav,
            string nsSuffix)
        {
            XmlNamespaceManager infoXmlNamespaceManager =
                new XmlNamespaceManager(infoNav.NameTable);

            infoXmlNamespaceManager.AddNamespace(
                "wc",
                "urn:com.microsoft.wc.methods.response." + nsSuffix);
            XPathExpression infoQueryIdPathClone = null;
            lock (_infoQueryIdPath)
            {
                infoQueryIdPathClone = _infoQueryIdPath.Clone();
            }

            infoQueryIdPathClone.SetContext(infoXmlNamespaceManager);

            return infoQueryIdPathClone;
        }

        private static OpenQuery CreateOpenQueryFromSaveOpenQueryResponse(
            XPathNavigator infoNav)
        {
            return CreateOpenQueryFromResponse(
                "SaveOpenQuery",
                infoNav);
        }

        private static OpenQuery CreateOpenQueryFromGetInfoResponse(
            XPathNavigator infoNav)
        {
            return CreateOpenQueryFromResponse(
                "GetOpenQueryInfo",
                infoNav);
        }

        private static OpenQuery CreateOpenQueryFromResponse(
            string rootNode,
            XPathNavigator infoNav)
        {
            OpenQuery oq = null;

            XPathExpression infoPath =
                GetInfoQueryIdXPathExpression(infoNav, rootNode);

            infoNav = infoNav.SelectSingleNode(infoPath);

            string queryIdString = infoNav.SelectSingleNode("query-id").Value;
            Guid queryId = new Guid(queryIdString);

            oq = new OpenQuery(queryId);

            oq._appName = infoNav.SelectSingleNode("app-name").Value;
            oq._createDate = infoNav.SelectSingleNode("date-created").ValueAsDateTime;

            XPathNavigator nav = infoNav.SelectSingleNode("expires-date");
            if (nav != null)
                oq._expiresDate = nav.ValueAsDateTime;

            nav = infoNav.SelectSingleNode("pin-required");
            if (nav != null)
                oq._pinRequired = nav.ValueAsBoolean;

            nav = infoNav.SelectSingleNode("note");
            if (nav != null)
                oq._note = nav.Value;

            return oq;
        }

        private static string GetSaveOpenQueryParameters(
            HealthRecordSearcher searcher,
            int expires,
            string pinCode,
            string note,
            string finalXsl)
        {
            string searcherParameters = searcher.GetParametersXml();

            return GetSaveOpenQueryParameters(
                "GetThings",
                "3",
                searcher.Record.Id,
                expires,
                pinCode,
                note,
                finalXsl,
                searcherParameters);
        }

        private static string GetSaveOpenQueryParameters(
            string methodName,
            string methodVersion,
            Guid recordId,
            int expires,
            string pinCode,
            string note,
            string finalXsl,
            string methodParameters)
        {
            StringBuilder result = new StringBuilder(256);
            XmlWriter writer = null;
            try
            {
                writer = XmlWriter.Create(
                    result, SDKHelper.XmlUnicodeWriterSettings);
                writer.WriteElementString("expires", expires.ToString(CultureInfo.InvariantCulture));
                if (!String.IsNullOrEmpty(pinCode))
                    writer.WriteElementString("pin-code", pinCode);
                if (!String.IsNullOrEmpty(note))
                    writer.WriteElementString("note", note);
                writer.WriteElementString("method", methodName);
                writer.WriteElementString("method-version", methodVersion);
                if (recordId != Guid.Empty)
                    writer.WriteElementString("record-id", recordId.ToString());
                if (!String.IsNullOrEmpty(finalXsl))
                    writer.WriteElementString("final-xsl", finalXsl);
                writer.WriteStartElement("info");
                writer.WriteRaw(methodParameters);
                writer.WriteEndElement(); // </info>
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
            return result.ToString();
        }
    }
}

