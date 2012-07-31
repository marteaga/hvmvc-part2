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
    /// This class defines an authorization to use a single <see cref="Vocabulary"/> or a family of 
    /// Vocabularies in HealthVault.
    /// </summary>
    /// 
    public class VocabularyAuthorization
    {
        /// <summary>
        /// Creates a new instance of the <see cref="VocabularyAuthorization"/> class
        /// with permissions to access the specified vocabulary.
        /// </summary>
        /// 
        /// <param name="vocabularyFamily">
        /// The family of HealthVault Vocabularies.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="vocabularyFamily"/> parameter is <b>null</b> or <see cref="String.Empty"/>
        /// </exception>
        /// 
        public VocabularyAuthorization(string vocabularyFamily)
        {
            Validator.ThrowIfStringNullOrEmpty(vocabularyFamily, "vocabularyFamily");
            _vocabularyFamily = vocabularyFamily;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="VocabularyAuthorization"/> class
        /// with permissions to access the specified vocabulary or family of vocabularies.
        /// </summary>
        /// 
        /// <param name="vocabularyFamily">
        /// The family of HealthVault vocabularies.
        /// </param>
        /// 
        /// <param name="vocabularyName">
        /// The name of the HealthVault <see cref="Vocabulary"/>.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// If the <paramref name="vocabularyFamily"/> parameter is <b>null</b> or <see cref="String.Empty"/>
        /// --OR--
        /// if the <paramref name="vocabularyName"/> parameter is <b>null</b> or <see cref="String.Empty"/>
        /// </exception>
        /// 
        public VocabularyAuthorization(string vocabularyFamily, string vocabularyName)
        {
            Validator.ThrowIfStringNullOrEmpty(vocabularyFamily, "vocabularyFamily");
            Validator.ThrowIfStringNullOrEmpty(vocabularyName, "vocabularyName");

            _vocabularyFamily = vocabularyFamily;
            _vocabularyName = vocabularyName;
        }

        /// <summary>
        /// Gets the family of the HealthVault <see cref="Vocabulary"/> being represented.
        /// </summary>
        public string VocabularyFamily
        {
            get { return _vocabularyFamily; }
        }
        private string _vocabularyFamily;

        /// <summary>
        /// Gets the name of the HealthVault <see cref="Vocabulary"/> being represented.
        /// </summary>
        /// <remarks>
        /// The absence of a name, i.e. the name set to null, indicates that the Authorization 
        /// covers all the vocabularies in the HealthVault vocabulary family.
        /// </remarks>
        public string VocabularyName
        {
            get { return _vocabularyName; }
        }
        private string _vocabularyName;

        /// <summary>
        /// Gets the string representation of the <see cref="VocabularyAuthorization"/>.
        /// </summary>
        /// 
        /// <returns>
        /// The string representation of the <see cref="VocabularyAuthorization"/>.
        /// </returns>
        /// 
        public override string ToString()
        {
            StringBuilder result = new StringBuilder();
            result.Append(VocabularyFamily);
            if (!String.IsNullOrEmpty(VocabularyName)) 
            {
                result.Append(":");
                result.Append(VocabularyName);
            }
            return result.ToString();
        }

        /// <summary>
        /// Writes the vocabulary authorization to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the vocabulary authorization to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b>null</b>.
        /// </exception>
        /// 
        public void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);

            writer.WriteStartElement("vocabulary-authorization");
            writer.WriteElementString("family", VocabularyFamily);
            if (!String.IsNullOrEmpty(VocabularyName))
            {
                writer.WriteElementString("name", VocabularyName);
            }
            writer.WriteEndElement();
        }

        /// <summary>
        /// Parses the xml serialized form of the vocabulary authorization, to create a 
        /// <see cref="VocabularyAuthorization"/>.
        /// </summary>
        /// <param name="vocabularyAuthorizationXml">
        /// The xml representation of the VocabularyAuthorization.
        /// </param>
        /// <returns>
        /// A VocabularyAuthorization.
        /// </returns>
        public static VocabularyAuthorization ParseXml(
            XPathNavigator vocabularyAuthorizationXml)
        {
            Validator.ThrowIfArgumentNull(vocabularyAuthorizationXml, "vocabularyAuthorizationXml", "VocabAuthNavIsNull");

            string vocabularyFamily = vocabularyAuthorizationXml.SelectSingleNode("family").Value;
            XPathNavigator vocabularyNameNav =
                vocabularyAuthorizationXml.SelectSingleNode("name");
            string vocabularyName = vocabularyNameNav != null ? vocabularyNameNav.Value : null;
            return
                !String.IsNullOrEmpty(vocabularyName) ?
                new VocabularyAuthorization(vocabularyFamily, vocabularyName) :
                new VocabularyAuthorization(vocabularyFamily);
        }

        internal static Collection<VocabularyAuthorization> CreateFromXml(
            XPathNavigator vocabularyAuthorizationsNav)
        {
            XPathNodeIterator vocabularyAuthorizationsIter = 
                vocabularyAuthorizationsNav.Select("vocabulary-authorization");

            return CreateVocabularyAuthorizations(vocabularyAuthorizationsIter); 
        }

        internal static Collection<VocabularyAuthorization> CreateVocabularyAuthorizations(
            XPathNodeIterator vocabularyAuthorizationsIter)
        {
            Collection<VocabularyAuthorization> result = 
                new Collection<VocabularyAuthorization>();

            foreach (XPathNavigator vocabularyAuthorizationNav in vocabularyAuthorizationsIter)
            {
                VocabularyAuthorization auth = ParseXml(vocabularyAuthorizationNav);
                result.Add(auth);
            }
            return result; 
        }
    }
}
