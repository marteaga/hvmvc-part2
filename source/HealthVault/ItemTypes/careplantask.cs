// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace Microsoft.Health.ItemTypes
{
    /// <summary>
    /// A task defines an action to be performed by the user.
    /// </summary>
    ///
    public class CarePlanTask : HealthRecordItemData
    {
        /// <summary>
        /// Creates a new instance of the <see cref="CarePlanTask"/> class with default values.
        /// </summary>
        ///
        public CarePlanTask()
        {
        }
        
        /// <summary>
        /// Creates a new instance of the <see cref="CarePlanTask"/> class
        /// specifying mandatory values.
        /// </summary>
        ///
        /// <param name="name">
        /// Name of the task.
        /// </param>
        ///
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="name"/> is <b>null</b>.
        /// </exception>
        ///
        public CarePlanTask(CodableValue name)
        {
            Name = name;
        }
        
        /// <summary>
        /// Populates this <see cref="CarePlanTask"/> instance from the data in the specified XML.
        /// </summary>
        ///
        /// <param name="navigator">
        /// The XML to get the CarePlanTask data from.
        /// </param>
        ///
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="navigator"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);
            
            _name = new CodableValue();
            _name.ParseXml(navigator.SelectSingleNode("name"));
            _description = XPathHelper.GetOptNavValue(navigator, "description");
            _startDate = XPathHelper.GetOptNavValue<ApproximateDateTime>(navigator, "start-date");
            _endDate = XPathHelper.GetOptNavValue<ApproximateDateTime>(navigator, "end-date");
            _sequenceNumber = XPathHelper.GetOptNavValueAsInt(navigator, "sequence-number");
            _contact = XPathHelper.GetOptNavValue<PersonItem>(navigator, "contact");
            _recurrence = XPathHelper.GetOptNavValue<CarePlanTaskRecurrence>(navigator, "recurrence");
            _thingTypeVersionId = XPathHelper.GetOptNavValueAsGuid(navigator, "thing-type-version-id");
            _thingTypeXPath = XPathHelper.GetOptNavValue(navigator, "thing-type-xpath");
            _referenceId = XPathHelper.GetOptNavValue(navigator, "reference-id");
        }
        
        /// <summary>
        /// Writes the XML representation of the CarePlanTask into
        /// the specified XML writer.
        /// </summary>
        ///
        /// <param name="nodeName">
        /// The name of the outer node for the medical image study series.
        /// </param>
        ///
        /// <param name="writer">
        /// The XML writer into which the CarePlanTask should be
        /// written.
        /// </param>
        ///
        /// <exception cref="ArgumentException">
        /// If <paramref name="nodeName"/> parameter is <b>null</b> or empty.
        /// </exception>
        ///
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthRecordItemSerializationException">
        /// If <see cref="Name"/> is <b>null</b>.
        /// </exception>
        ///
        public override void WriteXml(string nodeName, XmlWriter writer)
        {
            Validator.ThrowIfStringNullOrEmpty(nodeName, "WriteXmlEmptyNodeName");
            Validator.ThrowIfWriterNull(writer);

            Validator.ThrowSerializationIfNull(_name, "CarePlanTaskNameNull");

            writer.WriteStartElement("task");
            {
                _name.WriteXml("name", writer);
                XmlWriterHelper.WriteOptString(writer, "description", _description);
                XmlWriterHelper.WriteOpt<ApproximateDateTime>(writer, "start-date", _startDate);
                XmlWriterHelper.WriteOpt<ApproximateDateTime>(writer, "end-date", _endDate);
                XmlWriterHelper.WriteOptInt(writer, "sequence-number", _sequenceNumber);
                XmlWriterHelper.WriteOpt<PersonItem>(writer, "contact", _contact);
                XmlWriterHelper.WriteOpt<CarePlanTaskRecurrence>(writer, "recurrence", _recurrence);
                XmlWriterHelper.WriteOptGuid(writer, "thing-type-version-id", _thingTypeVersionId);
                XmlWriterHelper.WriteOptString(writer, "thing-type-xpath", _thingTypeXPath);
                XmlWriterHelper.WriteOptString(writer, "reference-id", _referenceId);
            }

            writer.WriteEndElement();
        }
        
        /// <summary>
        /// Gets or sets name of the task.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about name the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "FXCop thinks that CodableValue is a collection, so it throws this error.")]
        public CodableValue Name
        {
            get
            {
                return _name;
            }
            
            set
            {
                Validator.ThrowIfArgumentNull(value, "Name", "CarePlanTaskNameNull");
                _name = value;
            }
        }
        
        private CodableValue _name;
        
        /// <summary>
        /// Gets or sets description of the task.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about description the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Description
        {
            get
            {
                return _description;
            }
            
            set
            {
                Validator.ThrowIfStringIsEmptyOrWhitespace(value, "Description");
                _description = value;
            }
        }
        
        private string _description;

        private static void ValidateDates(
            ApproximateDateTime startDate, 
            ApproximateDateTime endDate)
        {
            if (startDate != null && endDate != null)
            {
                if (startDate.ApproximateDate != null && endDate.ApproximateDate != null)
                {
                    Validator.ThrowArgumentExceptionIf(
                        startDate.CompareTo(endDate) > 0,
                        "StartDate and EndDate",
                        "CarePlanTaskDateInvalid");
                }
            }
        }

        /// <summary>
        /// Gets or sets the start date for the task.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about startDate the value should be set to <b>null</b>.
        /// </remarks>
        ///
        public ApproximateDateTime StartDate
        {
            get
            {
                return _startDate;
            }
            
            set
            {
                ValidateDates(value, _endDate);
                _startDate = value;
            }
        }
        
        private ApproximateDateTime _startDate;
        
        /// <summary>
        /// Gets or sets the end date for the task.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about endDate the value should be set to <b>null</b>.
        /// </remarks>
        ///
        public ApproximateDateTime EndDate
        {
            get
            {
                return _endDate;
            }
            
            set
            {
                ValidateDates(_startDate, value);
                _endDate = value;
            }
        }
        
        private ApproximateDateTime _endDate;
        
        /// <summary>
        /// Gets or sets sequence number associated with the task.
        /// </summary>
        /// 
        /// <remarks>
        /// Sequence number could be used to decide the order in which the tasks should be performed.
        /// </remarks>
        ///
        public int? SequenceNumber
        {
            get
            {
                return _sequenceNumber;
            }
            
            set
            {
                 Validator.ThrowArgumentExceptionIf(
                     value < 0,
                    "SequenceNumber",
                    "CarePlanTaskSequenceNumberInvalid");

                _sequenceNumber = value;
            }
        }
        
        private int? _sequenceNumber;
        
        /// <summary>
        /// Gets or sets contact person associated with the task.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about contact the value should be set to <b>null</b>.
        /// </remarks>
        ///
        public PersonItem Contact
        {
            get
            {
                return _contact;
            }
            
            set
            {
                _contact = value;
            }
        }
        
        private PersonItem _contact;
        
        /// <summary>
        /// Gets or sets recurrence of the task.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about recurrence the value should be set to <b>null</b>.
        /// </remarks>
        ///
        public CarePlanTaskRecurrence Recurrence
        {
            get
            {
                return _recurrence;
            }
            
            set
            {
                _recurrence = value;
            }
        }
        
        private CarePlanTaskRecurrence _recurrence;
        
        /// <summary>
        /// Gets or sets version id of the HealthVault type associated with this task.
        /// </summary>
        /// 
        /// <remarks>
        /// Thing type version id could be used to determine if the task has been completed. For example, a corresponding thing instance in the record might indicate that the user has performed the task.
        /// </remarks>
        ///
        public Guid? ThingTypeVersionId
        {
            get
            {
                return _thingTypeVersionId;
            }
            
            set
            {
                _thingTypeVersionId = value;
            }
        }
        
        private Guid? _thingTypeVersionId;
        
        /// <summary>
        /// Gets or sets xPath expression for the field associated with this task in the thing type.
        /// </summary>
        /// 
        /// <remarks>
        /// Thing type XPath value could be used to specify which element in a thing type defined by the thing-type-version-id can be used to determine if the task has been completed.
        /// If there is no information about thingTypeXpath the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string ThingTypeXPath
        {
            get
            {
                return _thingTypeXPath;
            }
            
            set
            {
                Validator.ThrowIfStringIsEmptyOrWhitespace(value, "ThingTypeXPath");
                _thingTypeXPath = value;
            }
        }
        
        private string _thingTypeXPath;
        
        /// <summary>
        /// Gets or sets an unique id to distinguish one task from another.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about referenceId the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string ReferenceId
        {
            get
            {
                return _referenceId;
            }
            
            set
            {
                Validator.ThrowIfStringIsEmptyOrWhitespace(value, "ReferenceId");
                _referenceId = value;
            }
        }
        
        private string _referenceId;
        
        /// <summary>
        /// Gets a string representation of the CarePlanTask.
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of the CarePlanTask.
        /// </returns>
        ///
        public override string ToString()
        {
            string result;

            if (_description == null)
            {
                result = _name.Text;
            }
            else
            {
                result = String.Format(
                    CultureInfo.CurrentUICulture,
                    ResourceRetriever.GetResourceString("CarePlanTaskFormat"),
                    _name.Text,
                    _description);
            }

            return result;
        }
    }
}
