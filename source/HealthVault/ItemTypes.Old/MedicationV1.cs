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
    /// Represents a medication health record item.
    /// </summary>
    /// <remarks>
    /// Note: Please use the new version of this data type instead of this version.
    /// </remarks>
    /// 
    public class MedicationV1 : HealthRecordItem
    {
        /// <summary>
        /// Creates a new instance of the <see cref="MedicationV1"/> class with default 
        /// values.
        /// </summary>
        /// 
        /// <remarks>
        /// The item is not added to the health record until the
        /// <see cref="Microsoft.Health.HealthRecordAccessor.NewItem(HealthRecordItem)"/> method 
        /// is called.
        /// </remarks>
        /// 
        public MedicationV1()
            : base(TypeId)
        {
        }

        /// <summary>
        /// The unique identifier for the item type.
        /// </summary>
        /// 
        public new static readonly Guid TypeId =
            new Guid("5C5F1223-F63C-4464-870C-3E36BA471DEF");

        /// <summary>
        /// Populates this medication instance from the data in the XML.
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the medication data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// If the first node in <paramref name="typeSpecificXml"/> is not
        /// a medication node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator itemNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode("medication");

            Validator.ThrowInvalidIfNull(itemNav, "MedicationUnexpectedNode");

            // <name>
            _name =
                XPathHelper.GetOptNavValue(itemNav, "name");

            // <code>
            _code.Clear();
            XPathNodeIterator codeIterator = itemNav.Select("code");
            foreach (XPathNavigator codeNav in codeIterator)
            {
                _code.Add(codeNav.ValueAsInt);
            }

            // <date-discontinued>
            _dateDiscontinued =
                XPathHelper.GetOptNavValue<ApproximateDateTime>(
                    itemNav,
                    "date-discontinued");

            // <date-filled>
            _dateFilled =
                XPathHelper.GetOptNavValue<ApproximateDateTime>(
                    itemNav,
                    "date-filled"); 

            // <date-prescribed>
            _datePrescribed =
                XPathHelper.GetOptNavValue<ApproximateDateTime>(
                    itemNav,
                    "date-prescribed");

            // <is-prescribed>
            _isPrescribed =
                XPathHelper.GetOptNavValueAsBool(itemNav, "is-prescribed");
            
            // <indication>
            _indication =
                XPathHelper.GetOptNavValue(itemNav, "indication");
            
            // <amount-prescribed>
            _amountPrescribed =
                XPathHelper.GetOptNavValue(itemNav, "amount-prescribed");

            // <dose-value>
            _doseValue = 
                XPathHelper.GetOptNavValue<DoseValue>(itemNav, "dose-value");

            // <dose-unit>
            _doseUnit =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "dose-unit");

            // <strength-value>
            _strengthValue =
                XPathHelper.GetOptNavValueAsInt(itemNav, "strength-value");

            // <strength-unit>
            _strengthUnit =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "strength-unit");

            // <frequency>
            _frequency =
                XPathHelper.GetOptNavValue(itemNav, "frequency");

            // <route>
            _route =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "route");

            // <duration>
            _duration =
                XPathHelper.GetOptNavValue(
                    itemNav,
                    "duration");

            // <duration-unit>
            _durationUnit =
                XPathHelper.GetOptNavValue<CodableValue>(
                    itemNav,
                    "duration-unit");

            // <refills>
            _refills =
                XPathHelper.GetOptNavValueAsInt(itemNav, "refills");

            // <refills-left>
            _refillsLeft =
                XPathHelper.GetOptNavValueAsInt(itemNav, "refills-left");

            // <days-supply>
            _daysSupply =
                XPathHelper.GetOptNavValueAsInt(itemNav, "days-supply");

            // <prescription-duration>
            _prescriptionDuration =
                XPathHelper.GetOptNavValue<DurationValue>(
                    itemNav,
                    "prescription-duration");

            // <instructions>
            _instructions =
                XPathHelper.GetOptNavValue(itemNav, "instructions");

            // <substitution-permitted>
            _substitutionPermitted =
                XPathHelper.GetOptNavValueAsBool(
                    itemNav, 
                    "substitution-permitted");

            // <pharmacy>
            _pharmacy =
                XPathHelper.GetOptNavValue<ContactInfo>(
                    itemNav,
                    "pharmacy");

            // <prescription-number>
            _prescriptionNumber =
                XPathHelper.GetOptNavValue(
                    itemNav,
                    "prescription-number");
        }

        /// <summary>
        /// Writes the medication data to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the medication data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b>null</b>.
        /// </exception>
        /// 
        public override void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);

            // <medication>
            writer.WriteStartElement("medication");

            XmlWriterHelper.WriteOptString(
                writer,
                "name",
                Name);

            // <code>
            if (_code.Count > 0)
            {
                foreach (int code in _code)
                {
                    writer.WriteElementString(
                        "code",
                        code.ToString(CultureInfo.InvariantCulture));
                }
            }

            // <date-discontinued>
            XmlWriterHelper.WriteOpt<ApproximateDateTime>(
                writer,
                "date-discontinued",
                DateDiscontinued);

            // <date-filled>
            XmlWriterHelper.WriteOpt<ApproximateDateTime>(
                writer,
                "date-filled",
                DateFilled);
            
            // <date-prescribed>
            XmlWriterHelper.WriteOpt<ApproximateDateTime>(
                writer,
                "date-prescribed",
                DatePrescribed);

            // <is-prescribed>
            XmlWriterHelper.WriteOptBool(
                writer,
                "is-prescribed",
                _isPrescribed);

            // <indication>
            XmlWriterHelper.WriteOptString(
                writer,
                "indication",
                _indication);
            
            // <amount-prescribed>
            XmlWriterHelper.WriteOptString(
                writer,
                "amount-prescribed",
                _amountPrescribed);

            // <dose-value>
            XmlWriterHelper.WriteOpt<DoseValue>(
                writer,
                "dose-value",
                _doseValue);

            // <dose-unit>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "dose-unit",
                DoseUnit);

            // <strength-value>
            XmlWriterHelper.WriteOptInt(
                writer,
                "strength-value",
                _strengthValue);
            
            // <strength-unit>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "strength-unit",
                StrengthUnit);

            // <frequency>
            XmlWriterHelper.WriteOptString(
                writer,
                "frequency",
                _frequency);

            // <route>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "route",
                Route);

            // <duration>
            XmlWriterHelper.WriteOptString(
                writer,
                "duration",
                _duration);

            // <duration-unit>
            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "duration-unit",
                _durationUnit);

            // <refills>
            XmlWriterHelper.WriteOptInt(
                writer,
                "refills",
                _refills);
            
            // <refills-left>
            XmlWriterHelper.WriteOptInt(
                writer,
                "refills-left",
                _refillsLeft);
            
            // <days-supply>
            XmlWriterHelper.WriteOptInt(
                writer,
                "days-supply",
                _daysSupply);

            // <prescription-duration>
            XmlWriterHelper.WriteOpt<DurationValue>(
                writer,
                "prescription-duration",
                _prescriptionDuration);

            // <instructions>
            XmlWriterHelper.WriteOptString(
                writer,
                "instructions",
                _instructions);


            // <substitution-permitted>
            XmlWriterHelper.WriteOptBool(
                writer,
                "substitution-permitted",
                _substitutionPermitted);

            // <pharmacy>
            XmlWriterHelper.WriteOpt<ContactInfo>(
                writer,
                "pharmacy",
                _pharmacy);

            // prescription-number>
            XmlWriterHelper.WriteOptString(
                writer,
                "prescription-number",
                _prescriptionNumber);

            // </medication>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the medication name.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the name.
        /// </returns>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Name
        {
            get { return _name; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Name");
                _name = value;
            }
        }
        private string _name;

        /// <summary>
        /// Gets one or more medication codes.
        /// </summary>
        /// 
        /// <returns>
        /// A collection of integers representing the medication code or codes.
        /// </returns>
        /// 
        public Collection<int> Code
        {
            get { return _code; }
        }
        private Collection<int> _code = new Collection<int>();

        /// <summary>
        /// Gets or sets the date the medication was discontinued.
        /// </summary>
        /// 
        /// <returns>
        /// An <see cref="ApproximateDateTime"/> instance representing the date.
        /// </returns>
        /// 
        public ApproximateDateTime DateDiscontinued
        {
            get { return _dateDiscontinued; }
            set { _dateDiscontinued = value; }
        }
        private ApproximateDateTime _dateDiscontinued;

        /// <summary>
        /// Gets or sets the date the medication was filled.
        /// </summary>
        /// 
        /// <returns>
        /// An <see cref="ApproximateDateTime"/> instance representing the date.
        /// </returns>
        /// 
        public ApproximateDateTime DateFilled
        {
            get { return _dateFilled; }
            set { _dateFilled = value; }
        }
        private ApproximateDateTime _dateFilled;

        /// <summary>
        /// Gets or sets the date the medication was prescribed.
        /// </summary>
        /// 
        /// <returns>
        /// An <see cref="ApproximateDateTime"/> instance representing the date.
        /// </returns>
        /// 
        public ApproximateDateTime DatePrescribed
        {
            get { return _datePrescribed; }
            set { _datePrescribed = value; }
        }
        private ApproximateDateTime _datePrescribed;

        /// <summary>
        /// Gets whether medication is prescribed.
        /// </summary>
        /// 
        /// <returns>
        /// <b>true</b> if medication has been prescribed, <b>false</b> if 
        /// medication has not been prescribed, or <b>null</b> if t is unknown 
        /// whether medication is prescribed.
        /// </returns>
        /// 
        public bool? IsPrescribed
        {
            get { return _isPrescribed; }
            set { _isPrescribed = value; }
        }
        private bool? _isPrescribed;

        /// <summary>
        /// Gets or sets the indication for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the indication.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the indication should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Indication
        {
            get { return _indication; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Indication");
                _indication = value;
            }
        }
        private string _indication;
        
        /// <summary>
        /// Gets or sets the amount of medication prescribed.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the amount.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the amount should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string AmountPrescribed
        {
            get { return _amountPrescribed; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "AmountPrescribed");
                _amountPrescribed = value;
            }
        }
        private string _amountPrescribed;

        /// <summary>
        /// Gets or sets the dose value for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the dose value.
        /// </returns> 
        /// 
        /// <remarks>
        /// If the dose value is unknown, set the value to <b>null</b>.
        /// </remarks>
        /// 
        public DoseValue DoseValue
        {
            get { return _doseValue; }
            set { _doseValue = value; }
        }
        private DoseValue _doseValue;

        /// <summary>
        /// Gets or sets the dose unit for the medication prescribed.
        /// </summary>
        /// 
        /// <returns>
        /// An instance of <see cref="CodableValue"/> representing the dose unit.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the dose unit should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue DoseUnit
        {
            get { return _doseUnit; }
            set { _doseUnit = value; }
        }
        private CodableValue _doseUnit;

        /// <summary>
        /// Gets or sets the strength value for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the strength value.
        /// </returns> 
        /// 
        /// <remarks>
        /// If the strength value is unknown, the value can be set to
        /// <b>null</b>.
        /// </remarks>
        /// 
        public int? StrengthValue
        {
            get { return _strengthValue; }
            set { _strengthValue = value; }
        }
        private int? _strengthValue;
        

        /// <summary>
        /// Gets or sets the strength unit for the medication prescribed.
        /// </summary>
        /// 
        /// <returns>
        /// An instance of <see cref="CodableValue"/> representing the strength 
        /// unit.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the strength unit should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue StrengthUnit
        {
            get { return _strengthUnit; }
            set { _strengthUnit = value; }
        }
        private CodableValue _strengthUnit;

        /// <summary>
        /// Gets or sets the frequency for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the frequency.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the frequency should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Frequency
        {
            get { return _frequency; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Frequency");
                _frequency = value;
            }
        }
        private string _frequency;
        
        /// <summary>
        /// Gets or sets the route for the medication prescribed.
        /// </summary>
        /// 
        /// <returns>
        /// An instance of <see cref="CodableValue"/> representing the route.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the route should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue Route
        {
            get { return _route; }
            set { _route = value; }
        }
        private CodableValue _route;

        /// <summary>
        /// Gets or sets the duration for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the duration.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the duration should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Duration
        {
            get { return _duration; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Duration");
                _duration = value;
            }
        }
        private string _duration;

        /// <summary>
        /// Gets or sets the duration unit for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// An instance of <see cref="CodableValue"/> representing the duration 
        /// unit.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the duration unit should not be 
        /// stored.
        /// </remarks>
        /// 
        public CodableValue DurationUnit
        {
            get { return _durationUnit; }
            set { _durationUnit = value; }
        }
        private CodableValue _durationUnit;

        /// <summary>
        /// Gets or sets the number of total refills for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the number of refills.
        /// </returns> 
        /// 
        /// <remarks>
        /// If the number of refills is not known the value can be set to
        /// <b>null</b>.
        /// </remarks>
        /// 
        public int? Refills
        {
            get { return _refills; }
            set { _refills = value; }
        }
        private int? _refills;

        /// <summary>
        /// Gets or sets the number of remaining refills left of the medication.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the number of refills.
        /// </returns> 
        /// 
        /// <remarks>
        /// If the number of refills left is not known the value can be set to
        /// <b>null</b>.
        /// </remarks>
        /// 
        public int? RefillsLeft
        {
            get { return _refillsLeft; }
            set { _refillsLeft = value; }
        }
        private int? _refillsLeft;

        /// <summary>
        /// Gets or sets the days supply of the medication.
        /// </summary>
        /// 
        /// <returns>
        /// An integer representing the days supply.
        /// </returns> 
        /// 
        /// <remarks>
        /// If the days supply is not known the value can be set to
        /// <b>null</b>.
        /// </remarks>
        /// 
        public int? DaysSupply
        {
            get { return _daysSupply; }
            set { _daysSupply = value; }
        }
        private int? _daysSupply;

        /// <summary>
        /// Gets or sets the duration of the prescription.
        /// </summary>
        /// 
        /// <returns>
        /// A <see cref="DurationValue"/> instance representing the duration.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the prescription duration should not be 
        /// stored.
        /// </remarks>
        /// 
        public DurationValue PrescriptionDuration
        {
            get { return _prescriptionDuration; }
            set { _prescriptionDuration = value; }
        }
        private DurationValue _prescriptionDuration;

        /// <summary>
        /// Gets or sets the instructions for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the instructions.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the instructions should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Instructions
        {
            get { return _instructions; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Instructions");
                _instructions = value;
            }
        }
        private string _instructions;    

        /// <summary>
        /// Gets a value indicating whether a substitution for the medication 
        /// is permitted.
        /// </summary>
        /// 
        /// <returns>
        /// <b>true</b> if a substitute medication is permitted, <b>false</b> if a substitute 
        /// medication is not permitted, or <b>null</b> if it is unknown whether a 
        /// substitution is permitted.
        /// </returns> 
        /// 
        public bool? SubstitutionPermitted
        {
            get { return _substitutionPermitted; }
            set { _substitutionPermitted = value; }
        }
        private bool? _substitutionPermitted;

        /// <summary>
        /// Gets or sets the pharmacy contact information.
        /// </summary>
        /// 
        /// <returns>
        /// An instance of <see cref="ContactInfo"/> representing the pharmacy 
        /// information.
        /// </returns>
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the pharmacy contact information
        /// should not be stored.
        /// </remarks>
        /// 
        public ContactInfo Pharmacy
        {
            get { return _pharmacy; }
            set { _pharmacy = value; }
        }
        private ContactInfo _pharmacy;
        
        /// <summary>
        /// Gets or sets the prescription number for the medication.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the prescription number.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the prescription number should not be 
        /// stored.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string PrescriptionNumber
        {
            get { return _prescriptionNumber; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "PrescriptionNumber");
                _prescriptionNumber = value;
            }
        }
        private string _prescriptionNumber;

        /// <summary>
        /// Gets a string representation of the medication.
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of the medication.
        /// </returns>
        /// 
        public override string ToString()
        {
            StringBuilder result = new StringBuilder(100);

            if (Name != null)
            {
                result.Append(Name);
            }

            if (DoseValue != null)
            {
                if (result.Length > 0)
                {
                    result.Append(
                        ResourceRetriever.GetResourceString(
                            "ListSeparator"));
                }

                if (DoseValue.Description == null &&
                    DoseUnit != null)
                {
                    result.AppendFormat(
                        ResourceRetriever.GetResourceString(
                            "MedicationToStringFormatValueUnit"),
                        DoseValue.ToString(),
                        DoseUnit.Text);
                }
                else
                {
                    result.Append(DoseValue.ToString());
                }
            }

            if (StrengthValue != null)
            {
                if (result.Length > 0)
                {
                    result.Append(
                        ResourceRetriever.GetResourceString(
                            "ListSeparator"));
                }

                if (StrengthUnit != null)
                {
                    result.AppendFormat(
                        ResourceRetriever.GetResourceString(
                            "MedicationToStringFormatValueUnit"),
                        StrengthValue.Value,
                        StrengthUnit.Text);
                }
                else
                {
                    result.Append(StrengthValue.Value);
                }
            }

            if (Instructions != null)
            {
                if (result.Length > 0)
                {
                    result.Append(
                        ResourceRetriever.GetResourceString(
                            "ListSeparator"));
                }
                result.Append(Instructions);
            }
            return result.ToString();
        }
    }
}
