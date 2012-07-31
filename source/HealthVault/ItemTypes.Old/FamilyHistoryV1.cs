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
    /// Represents a health record item type that encapsulates a family history.
    /// </summary>
    /// <remarks>Note: Please use the new version of this data type instead of this version.
    /// </remarks>
    /// 
    public class FamilyHistoryV1 : HealthRecordItem
    {
        /// <summary>
        /// Creates a new instance of the <see cref="FamilyHistoryV1"/> class 
        /// with default values.
        /// </summary>
        /// 
        /// <remarks>
        /// The item is not added to the health record until the
        /// <see cref="Microsoft.Health.HealthRecordAccessor.NewItem(HealthRecordItem)"/> method 
        /// is called.
        /// </remarks>
        /// 
        public FamilyHistoryV1()
            : base(TypeId)
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="FamilyHistoryV1"/> class 
        /// specifying the mandatory values.
        /// </summary>
        /// 
        /// <param name="condition">
        /// The condition for the family history.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="condition"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public FamilyHistoryV1(CodableValue condition)
            : base(TypeId)
        {
            this.Condition = condition;
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
            new Guid("6D39F894-F7AC-4FCE-AC78-B22693BF96E6");

        /// <summary>
        /// Populates this family history instance from the data in the XML.
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the family history data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// The first node in <paramref name="typeSpecificXml"/> is not
        /// a family history node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator itemNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode("family-history");

            Validator.ThrowInvalidIfNull(itemNav, "FamilyHistoryUnexpectedNode");

            // <condition>
            _condition = new CodableValue();
            _condition.ParseXml(itemNav.SelectSingleNode("condition"));

            // <relationship>
            _relationship =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "relationship");

            // <date-of-birth>
            _dateOfBirth =
                XPathHelper.GetOptNavValue<ApproximateDate>(
                    itemNav,
                    "date-of-birth"); 
            
            // <age-of-onset>
            _ageOfOnset =
                XPathHelper.GetOptNavValueAsInt(
                    itemNav,
                    "age-of-onset");

            // <age-of-resolution>
            _ageOfResolution =
                XPathHelper.GetOptNavValueAsInt(
                    itemNav,
                    "age-of-resolution"); 
           
            // <duration>
            _duration =
                XPathHelper.GetOptNavValue<DurationValue>(
                    itemNav,
                    "duration"); 
            
            // <severity>
            _severity = XPathHelper.GetOptNavValue(itemNav, "severity");

            // <is-recurring>
            _isRecurring = 
                XPathHelper.GetOptNavValueAsBool(itemNav, "is-recurring");

            // <status>
            _status =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "status"); 
            
        }

        /// <summary>
        /// Writes the family history data to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the family history data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthRecordItemSerializationException">
        /// If <see cref="Condition"/> has not been set.
        /// </exception>
        /// 
        public override void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);
            Validator.ThrowSerializationIfNull(Condition, "FamilyHistoryConditionNotSet");

            // <family-history>
            writer.WriteStartElement("family-history");

            // <condition>
            Condition.WriteXml("condition", writer);

            // <relationship>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "relationship",
                Relationship);

            // <age-of-onset>
            XmlWriterHelper.WriteOptInt(
                writer,
                "age-of-onset",
                _ageOfOnset);           
            
            // <date-of-birth>
            XmlWriterHelper.WriteOpt<ApproximateDate>(
                writer,
                "date-of-birth",
                DateOfBirth); 

            
            // <age-of-resolution>
            XmlWriterHelper.WriteOptInt(
                writer,
                "age-of-resolution",
                _ageOfResolution); 
            
            // <duration>
            XmlWriterHelper.WriteOpt<DurationValue>(
                writer,
                "duration",
                Duration);

            // <severity>
            XmlWriterHelper.WriteOptString(
                writer,
                "severity",
                _severity);

            // <is-recurring>
            XmlWriterHelper.WriteOptBool(
                writer,
                "is-recurring",
                _isRecurring);

            // <status>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "status",
                Status);

            // </family-history>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the condition for the family history condition.
        /// </summary>
        /// 
        /// <value>
        /// An instance of <see cref="CodableValue"/> representing the condition.
        /// </value>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> is <b>null</b>.
        /// </exception>
        /// 
        public CodableValue Condition
        {
            get { return _condition; }
            set 
            {
                Validator.ThrowIfArgumentNull(value, "Condition", "FamilyHistoryConditionMandatory");
                _condition = value;
            }
        }
        private CodableValue _condition = new CodableValue();

        /// <summary>
        /// Gets or sets the relationship for the family history condition.
        /// </summary>
        /// 
        /// <value>
        /// An instance of <see cref="CodableValue"/> representing the 
        /// relationship.
        /// </value> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the relationship should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue Relationship
        {
            get { return _relationship; }
            set { _relationship = value; }
        }
        private CodableValue _relationship;

        /// <summary>
        /// Gets or sets the date of birth for the family history.
        /// </summary>
        /// 
        /// <value>
        /// An instance of <see cref="ApproximateDate"/> representing the date. 
        /// The default value is the current year, month, and day.
        /// </value> 
        /// 
        public ApproximateDate DateOfBirth
        {
            get { return _dateOfBirth; }
            set { _dateOfBirth = value; }
        }
        private ApproximateDate _dateOfBirth;

        /// <summary>
        /// Gets or sets the age of onset for the condition.
        /// </summary>
        /// 
        /// <value>
        /// An integer representing the age.
        /// </value>
        /// 
        /// <remarks>
        /// If the age of onset is not known, the value can be set to
        /// <b>null</b>.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="value"/> parameter is negative.
        /// </exception>
        /// 
        public int? AgeOfOnset
        {
            get { return _ageOfOnset; }
            set 
            {
                Validator.ThrowArgumentOutOfRangeIf(
                    value != null && value.Value < 0,
                    "AgeOfOnset",
                    "FamilyHistoryAgeOfOnsetNegative");
                _ageOfOnset = value; 
            }
        }
        private int? _ageOfOnset;

        /// <summary>
        /// Gets or sets the age of resolution for the condition.
        /// </summary>
        /// 
        /// <value>
        /// An integer representing the age.
        /// </value> 
        /// 
        /// <remarks>
        /// If the age of resolution is not known, the value can be set to
        /// <b>null</b>.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="value"/> parameter is negative.
        /// </exception>
        /// 
        public int? AgeOfResolution
        {
            get { return _ageOfResolution; }
            set
            {
                Validator.ThrowArgumentOutOfRangeIf(
                    value != null && value.Value < 0,
                    "AgeOfResolution",
                    "FamilyHistoryAgeOfResolutionNegative");
                _ageOfResolution = value;
            }
        }
        private int? _ageOfResolution;

        /// <summary>
        /// Gets or sets the duration for the family history condition.
        /// </summary>
        /// 
        /// <value>
        /// An instance of <see cref="DurationValue"/> representing the duration.
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
        /// Gets or sets the severity for the family history condition.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the severity.
        /// </value> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the severity should not be 
        /// stored.
        /// </remarks>
        /// 
        public string Severity
        {
            get { return _severity; }
            set { _severity = value; }
        }
        private string _severity;

        /// <summary>
        /// Gets or sets a value indicating whether this is a recurring 
        /// condition.
        /// </summary>
        /// 
        /// <remarks>
        /// <b>true</b> if this is a recurring condition; otherwise, <b>false</b>.
        /// If <b>null</b>, it is unknown whether this condition is recurring or not.
        /// </remarks>
        /// 
        public bool? IsRecurring
        {
            get { return _isRecurring; }
            set { _isRecurring = value; }
        }
        private bool? _isRecurring;

        /// <summary>
        /// Gets or sets the status for the family history condition.
        /// </summary>
        /// 
        /// <value>
        /// An instance of <see cref="CodableValue"/> representing 
        /// the status.
        /// </value>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the status should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue Status
        {
            get { return _status; }
            set { _status = value; }
        }
        private CodableValue _status;

        /// <summary>
        /// Gets a string representation of the family history item.
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of the family history item.
        /// </returns>
        /// 
        public override string ToString()
        {
            StringBuilder result = new StringBuilder(200);

            result.Append(Condition.Text);

            if (Relationship != null)
            {
                result.AppendFormat(
                    ResourceRetriever.GetResourceString(
                        "ListFormat"),
                    Relationship.Text);
            }

            if (AgeOfOnset != null)
            {
                result.AppendFormat(
                    ResourceRetriever.GetResourceString(
                        "FamilyHistoryToStringFormatAgeOfOnset"),
                    AgeOfOnset);
            }

            if (AgeOfResolution != null)
            {
                result.AppendFormat(
                    ResourceRetriever.GetResourceString(
                        "FamilyHistoryToStringFormatAgeOfResolution"),
                    AgeOfResolution);
            }

            return result.ToString();
        }
    }
}
