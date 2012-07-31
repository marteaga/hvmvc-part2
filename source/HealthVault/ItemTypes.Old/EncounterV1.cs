// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace Microsoft.Health.ItemTypes.Old
{
    /// <summary>
    /// Represents a health record item type that encapsulates a medical encounter.
    /// </summary>
    /// <remarks>
    /// Note: Please use the new version of this data type instead of this version.
    /// </remarks>
    /// 
    public class EncounterV1 : HealthRecordItem
    {
        /// <summary>
        /// Creates a new instance of the <see cref="EncounterV1"/> class with default values.
        /// </summary>
        /// 
        /// <remarks>
        /// The item is not added to the health record until the
        /// <see cref="Microsoft.Health.HealthRecordAccessor.NewItem(HealthRecordItem)"/> method 
        /// is called.
        /// </remarks>
        /// 
        public EncounterV1()
            : base(TypeId)
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="EncounterV1"/> class with the 
        /// specified date and time.
        /// </summary>
        /// 
        /// <param name="when">
        /// The date/time for the medical encounter.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="when"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public EncounterV1(HealthServiceDateTime when)
            : base(TypeId)
        {
            this.When = when;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="EncounterV1"/> class with the 
        /// specified date and time.
        /// </summary>
        /// 
        /// <param name="when">
        /// The date/time for the medical encounter.
        /// </param>
        /// 
        /// <param name="type">
        /// The type of the medical encounter.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="when"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="type"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        public EncounterV1(
            HealthServiceDateTime when,
            string type)
            : base(TypeId)
        {
            this.When = when;
            this.Type = type;
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
            new Guid("3D4BDF01-1B3E-4AFC-B41C-BD3E641A6DA7");

        /// <summary>
        /// Populates this medical encounter instance from the data in the XML.
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the medical encounter data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// The first node in <paramref name="typeSpecificXml"/> is not
        /// a medical encounter node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator itemNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode("encounter");

            Validator.ThrowInvalidIfNull(itemNav, "EncounterUnexpectedNode");

            // <when>
            _when = new HealthServiceDateTime();
            _when.ParseXml(itemNav.SelectSingleNode("when"));

            // <type>
            _type = XPathHelper.GetOptNavValue(itemNav, "type");

            // <id>
            _id = XPathHelper.GetOptNavValue(itemNav, "id");

            // <duration>
            _duration =
                XPathHelper.GetOptNavValue<DurationValue>(
                    itemNav,
                    "duration");

            // <location>
            _location =
                XPathHelper.GetOptNavValue<Address>(
                    itemNav,
                    "location"); 

            // <consent-granted>
            _consentGranted = 
                XPathHelper.GetOptNavValueAsBool(
                    itemNav, 
                    "consent-granted");
        }

        /// <summary>
        /// Writes the medical encounter data to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the medical encounter data to.
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
            Validator.ThrowSerializationIfNull(_when, "EncounterWhenNotSet");
            Validator.ThrowSerializationIf(String.IsNullOrEmpty(_type), "EncounterTypeNotSet");

            // <encounter>
            writer.WriteStartElement("encounter");

            // <when>
            _when.WriteXml("when", writer);

            // <type>
            XmlWriterHelper.WriteOptString(
                writer,
                "type",
                _type);

            // <id>
            XmlWriterHelper.WriteOptString(
                writer,
                "id",
                _id);

            // <duration>
            XmlWriterHelper.WriteOpt<DurationValue>(
                writer,
                "duration",
                _duration);

            // <location>
            XmlWriterHelper.WriteOpt<Address>(
                writer,
                "location",
                _location);

            // <consent-granted>
            XmlWriterHelper.WriteOptBool(
                writer,
                "consent-granted",
                _consentGranted);

            // </encounter>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the date/time when the medical encounter occurred.
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
        /// Gets or sets the type of medical encounter.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the encounter type.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the type should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> is <b>null</b>, empty, or contains only whitespace.
        /// </exception>
        /// 
        public string Type
        {
            get { return _type; }
            set 
            {
                Validator.ThrowIfStringNullOrEmpty(value, "Type");
                Validator.ThrowIfStringIsWhitespace(value, "Type");
                _type = value; 
            }
        }
        private string _type;

        /// <summary>
        /// Gets or sets the identifier for the medical encounter.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the encounter identifier.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the identifier should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Id
        {
            get { return _id; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Id");
                _id = value;
            }
        }
        private string _id;

        /// <summary>
        /// Gets or sets the encounter duration.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="DurationValue"/>.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the duration should not be 
        /// stored.
        /// </remarks>
        /// 
        public DurationValue Duration
        {
            get { return _duration; }
            set { _duration = value; }
        }
        private DurationValue _duration;

        /// <summary>
        /// Gets or sets the encounter location.
        /// </summary>
        /// 
        /// <value>
        /// An <see cref="Address"/> representing the location.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the location should not be 
        /// stored.
        /// </remarks>
        /// 
        public Address Location
        {
            get { return _location; }
            set { _location = value; }
        }
        private Address _location;
        
        /// <summary>
        /// Gets a value indicating whether consent has been granted.
        /// </summary>
        /// 
        /// <value>
        /// <b>true</b>if consent has been granted for this medical encounter; 
        /// otherwise, <b>false</b>. If <b>null</b>, it is unknown whether consent has been granted.
        /// </value>
        /// 
        public bool? ConsentGranted
        {
            get { return _consentGranted; }
            set { _consentGranted = value; }
        }
        private bool? _consentGranted;

        /// <summary>
        /// Gets a string representation of the encounter item.
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of the encounter item.
        /// </returns>
        /// 
        public override string ToString()
        {
            StringBuilder result = new StringBuilder(200);

            result.Append(When.ToString());

            if (Type != null)
            {
                result.AppendFormat(
                    ResourceRetriever.GetResourceString(
                        "ListFormat"),
                    Type);
            }

            if (Duration != null)
            {
                result.AppendFormat(
                    ResourceRetriever.GetResourceString(
                        "ListFormat"),
                    Duration.ToString());
            }

            if (Location != null)
            {
                result.AppendFormat(
                    ResourceRetriever.GetResourceString(
                        "ListFormat"),
                    Location.ToString());
            }

            return result.ToString();
        }
    }
}
