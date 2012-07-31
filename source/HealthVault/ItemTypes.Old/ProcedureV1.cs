// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Xml;
using System.Xml.XPath;

namespace Microsoft.Health.ItemTypes.Old
{
    /// <summary>
    /// Represents a health record item type that encapsulates a medical procedure.
    /// </summary>
    /// <remarks>
    /// Note: Please use the new version of this data type instead of this version.
    /// </remarks>
    /// 
    public class ProcedureV1 : HealthRecordItem
    {
        /// <summary>
        /// Creates a new instance of the <see cref="ProcedureV1"/> class with default 
        /// values.
        /// </summary>
        /// 
        /// <remarks>
        /// The item is not added to the health record until the
        /// <see cref="Microsoft.Health.HealthRecordAccessor.NewItem(HealthRecordItem)"/> method 
        /// is called.
        /// </remarks>
        /// 
        public ProcedureV1()
            : base(TypeId)
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="ProcedureV1"/> class with the 
        /// specified date and time.
        /// </summary>
        /// 
        /// <param name="when">
        /// The date/time for the procedure.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="when"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public ProcedureV1(HealthServiceDateTime when)
            : base(TypeId)
        {
            this.When = when;
        }

        /// <summary>
        /// Retrieves the unique identifier for the item type.
        /// </summary>
        /// 
        /// <value>
        /// A GUID.
        /// </value>
        /// 
        public new static readonly Guid TypeId =
            new Guid("0A5F9A43-DC88-4E9F-890F-1F9159B76E7B");

        /// <summary>
        /// Populates this procedure instance from the data in the XML.
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the procedure data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// The first node in <paramref name="typeSpecificXml"/> is not
        /// a procedure node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator itemNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode("procedure");

            Validator.ThrowInvalidIfNull(itemNav, "ProcedureUnexpectedNode");

            _when = new HealthServiceDateTime();
            _when.ParseXml(itemNav.SelectSingleNode("when"));

            // <title>
            _title =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "title");
            
            // <primary-provider>
            _primaryProvider =
                XPathHelper.GetOptNavValue<PersonItem>(
                    itemNav,
                    "primary-provider");

            // <anatomic-location>
            _anatomicLocation =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "anatomic-location");

            // <secondary-provider>
            _secondaryProvider =
                XPathHelper.GetOptNavValue<PersonItem>(
                    itemNav,
                    "secondary-provider");
        }

        /// <summary>
        /// Writes the procedure data to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the procedure data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthRecordItemSerializationException">
        /// The <see cref="When"/> property has not been set.
        /// </exception>
        /// 
        public override void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);
            Validator.ThrowSerializationIfNull(_when, "ProcedureWhenNotSet");

            // <procedure>
            writer.WriteStartElement("procedure");

            // <when>
            _when.WriteXml("when", writer);

            // <title>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "title",
                _title);

            // <primary-provider>
            XmlWriterHelper.WriteOpt<PersonItem>(
                writer,
                "primary-provider",
                _primaryProvider);

            // <anatomic-location>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "anatomic-location",
                _anatomicLocation);

            // <secondary-provider>
            XmlWriterHelper.WriteOpt<PersonItem>(
                writer,
                "secondary-provider",
                _secondaryProvider);

            // </procedure>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the date/time when the procedure occurred.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="HealthServiceDateTime"/> instance representing 
        /// the date. The default value is the current year, month, and day.
        /// </value>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public HealthServiceDateTime When
        {
            get { return _when; }
            set
            {
                Validator.ThrowIfArgumentNull(value, "When", "WhenNullValue");
                _when = value;
            }
        }
        private HealthServiceDateTime _when = new HealthServiceDateTime();

        /// <summary>
        /// Gets or sets the title for the procedure.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="CodableValue"/> representing the title.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the title should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue Title
        {
            get { return _title; }
            set { _title = value; }
        }
        private CodableValue _title;

        /// <summary>
        /// Gets or sets the primary provider contact information.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="PersonItem"/> representing the information.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the primary provider contact information
        /// should not be stored.
        /// </remarks>
        /// 
        public PersonItem PrimaryProvider
        {
            get { return _primaryProvider; }
            set { _primaryProvider = value; }
        }
        private PersonItem _primaryProvider;

        /// <summary>
        /// Gets or sets the anatomic location for the procedure.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="CodableValue"/> representing the location.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the location should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue AnatomicLocation
        {
            get { return _anatomicLocation; }
            set { _anatomicLocation = value; }
        }
        private CodableValue _anatomicLocation;

        /// <summary>
        /// Gets or sets the secondary provider contact information.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="PersonItem"/> representing the information.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the secondary provider contact information
        /// should not be stored.
        /// </remarks>
        /// 
        public PersonItem SecondaryProvider
        {
            get { return _secondaryProvider; }
            set { _secondaryProvider = value; }
        }
        private PersonItem _secondaryProvider;

        /// <summary>
        /// Gets a string representation of the procedure.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the procedure.
        /// </returns>
        /// 
        public override string ToString()
        {
            string result = String.Empty;

            if (Title != null)
            {
                result = Title.Text;
            }
            return result;
        }

    }
}
