// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace Microsoft.Health
{
    /// <summary>
    /// Provides information about the HealthVault service to which you are 
    /// connected.
    /// </summary>
    /// 
    public class ServiceInfo
    {
        internal static ServiceInfo CreateServiceInfo(XPathNavigator nav)
        {
            Uri platformUrl =
                new Uri(nav.SelectSingleNode("platform/url").Value);

            string platformVersion =
                nav.SelectSingleNode("platform/version").Value;

            Dictionary<string, string> configValues =
                GetConfigurationValues(nav.Select("platform/configuration"));

            HealthServiceShellInfo shellInfo 
                = HealthServiceShellInfo.CreateShellInfo(
                    nav.SelectSingleNode("shell"));

            Collection<HealthServiceMethodInfo> methods = GetMethods(nav);
            Collection<Uri> includes = GetIncludes(nav);

            ServiceInfo serviceInfo = 
                new ServiceInfo(
                    platformUrl,
                    platformVersion,
                    shellInfo,
                    methods,
                    includes,
                    configValues);

            return serviceInfo;
        }

        private static Dictionary<string, string> GetConfigurationValues(
            XPathNodeIterator configIterator)
        {
            Dictionary<string, string> result = new Dictionary<string, string>();

            foreach (XPathNavigator configNav in configIterator)
            {
                result.Add(configNav.GetAttribute("key", String.Empty), configNav.Value);
            }
            return result;
        }

        private static Collection<HealthServiceMethodInfo> GetMethods(
            XPathNavigator nav)
        {
            XPathNodeIterator methodNavs = nav.Select("xml-method");
            Collection<HealthServiceMethodInfo> methods =
                new Collection<HealthServiceMethodInfo>();

            foreach (XPathNavigator methodNav in methodNavs)
            {
                methods.Add(HealthServiceMethodInfo.CreateMethodInfo(methodNav));
            }
            return methods;
        }

        private static Collection<Uri> GetIncludes(
            XPathNavigator nav)
        {
            Collection<Uri> includes = new Collection<Uri>();
            XPathNodeIterator includeNavs = nav.Select("common-schema");

            foreach (XPathNavigator includeNav in includeNavs)
            {
                includes.Add(new Uri(includeNav.Value));
            }
            return includes;
        }

        private ServiceInfo(
            Uri healthServiceUrl,
            string healthVaultVersion,
            HealthServiceShellInfo shellInfo,
            IList<HealthServiceMethodInfo> methods,
            IList<Uri> includes,
            Dictionary<string, string> configurationValues)
        {
            _healthServiceUrl = healthServiceUrl;
            _healthVaultVersion = healthVaultVersion;
            _shellInfo = shellInfo;

            _methods = 
                new ReadOnlyCollection<HealthServiceMethodInfo>(methods);
            _includes = 
                new ReadOnlyCollection<Uri>(includes);

            if (configurationValues != null)
            {
                _configurationValues = configurationValues;
            }
        }

        /// <summary>
        /// Create a new instance of the <see cref="ServiceInfo"/> class for testing purposes.
        /// </summary>
        protected ServiceInfo()
        {
        }

        /// <summary>
        /// Gets or sets the HealthVault URL.
        /// </summary>
        /// 
        /// <value>
        /// A Uri representing a URL to the HealthVault service.
        /// </value>
        /// 
        /// <remarks>
        /// This is the URL to the wildcat.ashx which is used to call the
        /// HealthVault XML methods.
        /// </remarks>
        /// 
        public Uri HealthServiceUrl
        {
            get { return _healthServiceUrl; }
            protected set { _healthServiceUrl = value; }
        }
        private Uri _healthServiceUrl;

        /// <summary>
        /// Gets or sets the version of the HealthVault service.
        /// </summary>
        /// 
        /// <value>
        /// A string indicating the version of the HealthVault Service.
        /// </value>
        /// 
        /// <remarks>
        /// This value is generally in the format of a 
        /// <see cref="System.Version"/>, but can be changed by the
        /// HealthVault service provider.
        /// </remarks>
        /// 
        public string Version
        {
            get { return _healthVaultVersion; }
            protected set { _healthVaultVersion = value; }
        }
        private string _healthVaultVersion;

        /// <summary>
        /// Gets or sets the latest information about the HealthVault Shell.
        /// </summary>
        /// 
        public HealthServiceShellInfo HealthServiceShellInfo
        {
            get { return _shellInfo; }
            protected set { _shellInfo = value; }
        }
        private HealthServiceShellInfo _shellInfo;

        /// <summary>
        /// Gets the latest information about the assemblies that represent 
        /// the HealthVault SDK.
        /// </summary>
        /// 
        /// <value>
        /// A read-only collection of information about the .NET assemblies
        /// that can be used as helpers for accessing the HealthVault service.
        /// </value>
        /// 
        /// <remarks>
        /// This property is no longer supported and will always return an empty 
        /// collection.
        /// </remarks>
        /// 
        [Obsolete("No longer supported - remove references to this property.")]
        public ReadOnlyCollection<HealthServiceAssemblyInfo> Assemblies
        {
            get 
            { 
                return 
                    new ReadOnlyCollection<HealthServiceAssemblyInfo>(
                        new HealthServiceAssemblyInfo[] {}); 
            }
        }

        /// <summary>
        /// Gets or sets information about the methods that the HealthVault service
        /// exposes.
        /// </summary>
        /// 
        /// <value>
        /// A read-only collection of the HealthVault method definitions.
        /// </value>
        /// 
        /// <remarks>
        /// A HealthVault method is a named service point provided by the HealthVault
        /// service that answers HTTP requests that contain XML adhering to 
        /// the HealthVault request schema. The elements of this collection
        /// define the method name, and request and response schemas for the 
        /// method.
        /// </remarks>
        /// 
        public ReadOnlyCollection<HealthServiceMethodInfo> Methods
        {
            get { return _methods; }
            protected set { _methods = value; }
        }
        private ReadOnlyCollection<HealthServiceMethodInfo> _methods;

        /// <summary>
        /// Gets or sets the URLs of the common schemas that are included in the
        /// method XSDs.
        /// </summary>
        /// 
        /// <value>
        /// A read-only collection containing the URLs of the schemas that
        /// are included in the <see cref="Methods"/> request and response
        /// schemas.
        /// </value>
        /// 
        /// <remarks>
        /// Many of the <see cref="Methods"/> contain types that are common
        /// across different method requests and responses. These types are
        /// defined in the included schema URLs so that they can be referenced
        /// by each of the methods as needed.
        /// </remarks>
        /// 
        public ReadOnlyCollection<Uri> IncludedSchemaUrls
        {
            get { return _includes; }
            protected set { _includes = value; }
        }
        private ReadOnlyCollection<Uri> _includes;

        /// <summary>
        /// Gets or sets the public configuration values for the HealthVault service.
        /// </summary>
        /// 
        /// <value>
        /// The dictionary returned uses the configuration value name as the key. All entries are
        /// public configuration values that the HealthVault service exposes as information to 
        /// HealthVault applications. Values can be used to throttle health record item queries, etc.
        /// </value>
        /// 
        public Dictionary<string, string> ConfigurationValues
        {
            get { return _configurationValues; }
            protected set { _configurationValues = value; }
        }
        private Dictionary<string, string> _configurationValues = new Dictionary<string,string>();
    }
}
