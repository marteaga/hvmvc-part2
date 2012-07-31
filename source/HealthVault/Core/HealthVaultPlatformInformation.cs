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
    /// Provides low-level access to the HealthVault message operations.
    /// </summary>
    /// <remarks>
    /// <see cref="HealthVaultPlatform"/> uses this class to perform operations. Set 
    /// HealthVaultPlatformInformation.Current to a derived class to intercept all message calls.
    /// </remarks>

    public class HealthVaultPlatformInformation
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
        public static void EnableMock(HealthVaultPlatformInformation mock)
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
        internal static HealthVaultPlatformInformation Current
        {
            get { return _current; }
        }
        private static HealthVaultPlatformInformation _current = new HealthVaultPlatformInformation();
        private static HealthVaultPlatformInformation _saved;


        #region GetServiceDefinition

        /// <summary>
        /// Gets information about the HealthVault service.
        /// </summary>
        /// 
        /// <param name="connection">The connection to use to perform the operation. </param>
        /// 
        /// <remarks>
        /// Gets the latest information about the HealthVault service. This 
        /// includes:<br/>
        /// - The version of the service.<br/>
        /// - The SDK assembly URLs.<br/>
        /// - The SDK assembly versions.<br/>
        /// - The SDK documentation URL.<br/>
        /// - The URL to the HealthVault Shell.<br/>
        /// - The schema definition for the HealthVault method's request and 
        ///   response.
        /// - The common schema definitions for types that the HealthVault methods
        ///   use.<br/>
        /// </remarks>
        /// 
        /// <returns>
        /// A <see cref="ServiceInfo"/> instance that contains the service version, SDK
        /// assemblies versions and URLs, method information, and so on.
        /// </returns>
        /// 
        /// <exception cref="HealthServiceException">
        /// The HealthVault service returns an error.
        /// </exception>
        /// 
        /// <exception cref="UriFormatException">
        /// One or more URL strings returned by HealthVault is invalid.
        /// </exception> 
        /// 
        public virtual ServiceInfo GetServiceDefinition(HealthServiceConnection connection)
        {
            HealthServiceRequest request =
                new HealthServiceRequest(connection, "GetServiceDefinition", 2);
            request.Execute();

            XPathExpression infoPath = GetInfoXPathExpression(request.Response.InfoNavigator);
            XPathNavigator infoNav = request.Response.InfoNavigator.SelectSingleNode(infoPath);

            return ServiceInfo.CreateServiceInfo(infoNav);
        }

        private static XPathExpression _infoPath = XPathExpression.Compile("/wc:info");

        private static XPathExpression GetInfoXPathExpression(XPathNavigator infoNav)
        {
            XmlNamespaceManager infoXmlNamespaceManager =
                new XmlNamespaceManager(infoNav.NameTable);

            infoXmlNamespaceManager.AddNamespace(
                "wc", "urn:com.microsoft.wc.methods.response.GetServiceDefinition2");

            XPathExpression infoPathClone = null;
            lock (_infoPath)
            {
                infoPathClone = _infoPath.Clone();
            }

            infoPathClone.SetContext(infoXmlNamespaceManager);

            return infoPathClone;
        }
        #endregion GetServiceDefinition

        #region GetHealthRecordItemType

        /// <summary> 
        /// Removes all item type definitions from the client-side cache.
        /// </summary>
        /// 
        public virtual void ClearItemTypeCache()
        {
            lock (_sectionCache)
            {
                _sectionCache.Clear();
            }
        }

        private Dictionary<String, Dictionary<HealthRecordItemTypeSections, Dictionary<Guid, HealthRecordItemTypeDefinition>>>
            _sectionCache = new Dictionary<String, Dictionary<HealthRecordItemTypeSections, Dictionary<Guid, HealthRecordItemTypeDefinition>>>();


        /// <summary>
        /// Gets the definitions for one or more health record item type definitions
        /// supported by HealthVault.
        /// </summary>
        /// 
        /// <param name="typeIds">
        /// A collection of health item type IDs whose details are being requested. Null 
        /// indicates that all health item types should be returned.
        /// </param>
        /// 
        /// <param name="sections">
        /// A collection of HealthRecordItemTypeSections enumeration values that indicate the type 
        /// of details to be returned for the specified health item records(s).
        /// </param>
        /// 
        /// <param name="imageTypes">
        /// A collection of strings that identify which health item record images should be 
        /// retrieved.
        /// 
        /// This requests an image of the specified mime type should be returned. For example, 
        /// to request a GIF image, "image/gif" should be specified. For icons, "image/vnd.microsoft.icon" 
        /// should be specified. Note, not all health item records will have all image types and 
        /// some may not have any images at all.
        ///                
        /// If '*' is specified, all image types will be returned.
        /// </param>
        /// 
        /// <param name="lastClientRefreshDate">
        /// A <see cref="DateTime"/> instance that specifies the time of the last refresh
        /// made by the client.
        /// </param>
        /// 
        /// <param name="connection"> 
        /// A connection to the HealthVault service.
        /// </param>
        /// 
        /// <returns>
        /// The type definitions for the specified types, or empty if the
        /// <paramref name="typeIds"/> parameter does not represent a known unique
        /// type identifier.
        /// </returns>
        /// 
        /// <remarks>
        /// This method calls the HealthVault service if the types are not
        /// already in the client-side cache.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="typeIds"/> is <b>null</b> and empty, or 
        /// <paramref name="typeIds"/> is <b>null</b> and member in <paramref name="typeIds"/> is 
        /// <see cref="System.Guid.Empty"/>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="connection"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public virtual IDictionary<Guid, HealthRecordItemTypeDefinition> GetHealthRecordItemTypeDefinition(
            IList<Guid> typeIds,
            HealthRecordItemTypeSections sections,
            IList<String> imageTypes,
            DateTime? lastClientRefreshDate,
            HealthServiceConnection connection)
        {
            Validator.ThrowIfArgumentNull(connection, "connection", "TypeManagerConnectionNull");

            Validator.ThrowArgumentExceptionIf(
                (typeIds != null && typeIds.Contains(Guid.Empty)) ||
                (typeIds != null && typeIds.Count == 0),
                "typeIds",
                "TypeIdEmpty");

            if (lastClientRefreshDate != null)
            {
                return GetHealthRecordItemTypeDefinitionByDate(typeIds,
                                                               sections,
                                                               imageTypes,
                                                               lastClientRefreshDate.Value,
                                                               connection);
            }
            else
            {
                return GetHealthRecordItemTypeDefinitionNoDate(typeIds,
                                                               sections,
                                                               imageTypes,
                                                               connection);
            }
        }
        
        private IDictionary<Guid, HealthRecordItemTypeDefinition>
            GetHealthRecordItemTypeDefinitionNoDate(
                IList<Guid> typeIds,
                HealthRecordItemTypeSections sections,
                IList<String> imageTypes,
                HealthServiceConnection connection)
        {
            HealthServiceRequest request =
                new HealthServiceRequest(connection, "GetThingType", 1);

            StringBuilder requestParameters = new StringBuilder();
            XmlWriterSettings settings = SDKHelper.XmlUnicodeWriterSettings;
            settings.OmitXmlDeclaration = true;
            settings.ConformanceLevel = ConformanceLevel.Fragment;

            Dictionary<Guid, HealthRecordItemTypeDefinition> cachedThingTypes = null;

            string cultureName = connection.Culture.Name;
            Boolean sendRequest = false;

            using (XmlWriter writer = XmlWriter.Create(requestParameters, settings))
            {
                if ((typeIds != null) && (typeIds.Count > 0))
                {
                    foreach (Guid id in typeIds)
                    {
                        lock (_sectionCache)
                        {
                            if (!_sectionCache.ContainsKey(cultureName))
                            {
                                _sectionCache.Add(
                                    cultureName,
                                    new Dictionary<HealthRecordItemTypeSections, Dictionary<Guid, HealthRecordItemTypeDefinition>>());
                            }
                            if (!_sectionCache[cultureName].ContainsKey(sections))
                            {
                                _sectionCache[cultureName].Add(sections, new Dictionary<Guid, HealthRecordItemTypeDefinition>());
                            }

                            if (_sectionCache[cultureName][sections].ContainsKey(id))
                            {
                                if (cachedThingTypes == null)
                                {
                                    cachedThingTypes =
                                        new Dictionary<Guid, HealthRecordItemTypeDefinition>();
                                }

                                cachedThingTypes[id] = _sectionCache[cultureName][sections][id];
                            }
                            else
                            {
                                sendRequest = true;

                                writer.WriteStartElement("id");

                                writer.WriteString(id.ToString("D"));

                                writer.WriteEndElement();
                            }
                        }
                    }
                }
                else
                {
                    lock (_sectionCache)
                    {
                        if (!_sectionCache.ContainsKey(cultureName))
                        {
                            _sectionCache.Add(
                                cultureName,
                                new Dictionary<HealthRecordItemTypeSections, Dictionary<Guid, HealthRecordItemTypeDefinition>>());
                        }
                        if (!_sectionCache[cultureName].ContainsKey(sections))
                        {
                            _sectionCache[cultureName].Add(sections, new Dictionary<Guid, HealthRecordItemTypeDefinition>());

                        }
                        else
                        {
                            cachedThingTypes = _sectionCache[cultureName][sections];
                        }
                    }

                    sendRequest = true;
                }

                if (!sendRequest)
                {
                    return cachedThingTypes;
                }
                else
                {
                    WriteSectionSpecs(writer, sections);

                    if ((imageTypes != null) && (imageTypes.Count > 0))
                    {
                        foreach (string imageType in imageTypes)
                        {
                            writer.WriteStartElement("image-type");

                            writer.WriteString(imageType);

                            writer.WriteEndElement();
                        }
                    }

                    writer.Flush();
                }
                request.Parameters = requestParameters.ToString();

                request.Execute();

                Dictionary<Guid, HealthRecordItemTypeDefinition> result =
                    CreateThingTypesFromResponse(
                        cultureName,
                        request.Response,
                        sections,
                        cachedThingTypes);

                lock (_sectionCache)
                {
                    foreach (Guid id in result.Keys)
                    {
                        _sectionCache[cultureName][sections][id] = result[id];
                    }
                }

                return result;
            }
        }

        private IDictionary<Guid, HealthRecordItemTypeDefinition>
            GetHealthRecordItemTypeDefinitionByDate(
                IList<Guid> typeIds,
                HealthRecordItemTypeSections sections,
                IList<String> imageTypes,
                DateTime lastClientRefreshDate,
                HealthServiceConnection connection)
        {
            HealthServiceRequest request =
                new HealthServiceRequest(connection, "GetThingType", 1);

            StringBuilder requestParameters = new StringBuilder();
            XmlWriterSettings settings = SDKHelper.XmlUnicodeWriterSettings;
            settings.OmitXmlDeclaration = true;
            settings.ConformanceLevel = ConformanceLevel.Fragment;

            using (XmlWriter writer = XmlWriter.Create(requestParameters, settings))
            {
                if ((typeIds != null) && (typeIds.Count > 0))
                {
                    foreach (Guid id in typeIds)
                    {
                        writer.WriteStartElement("id");

                        writer.WriteString(id.ToString("D"));

                        writer.WriteEndElement();
                    }
                }

                WriteSectionSpecs(writer, sections);

                if ((imageTypes != null) && (imageTypes.Count > 0))
                {
                    foreach (string imageType in imageTypes)
                    {
                        writer.WriteStartElement("image-type");

                        writer.WriteString(imageType);

                        writer.WriteEndElement();
                    }
                }

                writer.WriteElementString("last-client-refresh",
                                          SDKHelper.XmlFromLocalDateTime(lastClientRefreshDate));

                writer.Flush();

                request.Parameters = requestParameters.ToString();

                request.Execute();

                Dictionary<Guid, HealthRecordItemTypeDefinition> result =
                    CreateThingTypesFromResponse(
                        connection.Culture.Name,
                        request.Response,
                        sections,
                        null);

                lock (_sectionCache)
                {
                    _sectionCache[connection.Culture.Name][sections] = result;
                }

                return result;
            }
        }

        private static void WriteSectionSpecs(XmlWriter writer,
                                              HealthRecordItemTypeSections sectionSpecs)
        {
            if ((sectionSpecs & HealthRecordItemTypeSections.Core) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.Core.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }

            if ((sectionSpecs & HealthRecordItemTypeSections.Xsd) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.Xsd.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }

            if ((sectionSpecs & HealthRecordItemTypeSections.Columns) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.Columns.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }

            if ((sectionSpecs & HealthRecordItemTypeSections.Transforms) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.Transforms.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }

            if ((sectionSpecs & HealthRecordItemTypeSections.TransformSource) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.TransformSource.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }

            if ((sectionSpecs & HealthRecordItemTypeSections.Versions) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.Versions.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }

            if ((sectionSpecs & HealthRecordItemTypeSections.EffectiveDateXPath) != HealthRecordItemTypeSections.None)
            {
                writer.WriteStartElement("section");
                writer.WriteString(HealthRecordItemTypeSections.EffectiveDateXPath.ToString().ToLowerInvariant());
                writer.WriteEndElement();
            }
        }

        private Dictionary<Guid, HealthRecordItemTypeDefinition> CreateThingTypesFromResponse(
            string cultureName,
            HealthServiceResponseData response,
            HealthRecordItemTypeSections sections,
            Dictionary<Guid, HealthRecordItemTypeDefinition> cachedThingTypes)
        {
            Dictionary<Guid, HealthRecordItemTypeDefinition> thingTypes = null;

            if (cachedThingTypes != null && cachedThingTypes.Count > 0)
            {
                thingTypes = new Dictionary<Guid, HealthRecordItemTypeDefinition>(cachedThingTypes);
            }
            else
            {
                thingTypes = new Dictionary<Guid, HealthRecordItemTypeDefinition>();
            }

            XPathNodeIterator thingTypesIterator =
                response.InfoNavigator.Select("thing-type");

            lock (_sectionCache)
            {
                if (!_sectionCache.ContainsKey(cultureName))
                {
                    _sectionCache.Add(cultureName, new Dictionary<HealthRecordItemTypeSections, Dictionary<Guid, HealthRecordItemTypeDefinition>>());
                }

                if (!_sectionCache[cultureName].ContainsKey(sections))
                {
                    _sectionCache[cultureName].Add(sections, new Dictionary<Guid, HealthRecordItemTypeDefinition>());
                }

                foreach (XPathNavigator navigator in thingTypesIterator)
                {
                    HealthRecordItemTypeDefinition thingType =
                        HealthRecordItemTypeDefinition.CreateFromXml(navigator);

                    _sectionCache[cultureName][sections][thingType.TypeId] = thingType;
                    thingTypes[thingType.TypeId] = thingType;
                }
            }

            return thingTypes;
        }
        #endregion GetHealthRecordItemType
    }
}

