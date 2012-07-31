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
    /// A goal defines a target for a measurement.
    /// </summary>
    ///
    public class CarePlanGoal : HealthRecordItemData
    {
        /// <summary>
        /// Creates a new instance of the <see cref="CarePlanGoal"/> class with default values.
        /// </summary>
        ///
        public CarePlanGoal()
        {
        }
        
        /// <summary>
        /// Creates a new instance of the <see cref="CarePlanGoal"/> class
        /// specifying mandatory values.
        /// </summary>
        ///
        /// <param name="name">
        /// Name of the goal.
        /// </param>
        ///
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="name"/> is <b>null</b>.
        /// </exception>
        ///
        public CarePlanGoal(CodableValue name)
        {
            Name = name;
        }
        
        /// <summary>
        /// Populates this <see cref="CarePlanGoal"/> instance from the data in the specified XML.
        /// </summary>
        ///
        /// <param name="navigator">
        /// The XML to get the CarePlanGoal data from.
        /// </param>
        ///
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="navigator"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);

            _name = XPathHelper.GetOptNavValue<CodableValue>(navigator, "name");
            _description = XPathHelper.GetOptNavValue(navigator, "description");
            _startDate = XPathHelper.GetOptNavValue<ApproximateDateTime>(navigator, "start-date");
            _endDate = XPathHelper.GetOptNavValue<ApproximateDateTime>(navigator, "end-date");
            _thingTypeVersionId = XPathHelper.GetOptNavValueAsGuid(navigator, "thing-type-version-id");
            _thingTypeValueXPath = XPathHelper.GetOptNavValue(navigator, "thing-type-value-xpath");
            _thingTypeDisplayXPath = XPathHelper.GetOptNavValue(navigator, "thing-type-display-xpath");
            _valueUnit = XPathHelper.GetOptNavValue<CodableValue>(navigator, "value-unit");
            _unitConversion = XPathHelper.GetOptNavValue<UnitConversion>(navigator, "unit-conversion");

            _goalRanges = XPathHelper.ParseXmlCollection<CarePlanGoalRange>(navigator, "goal-ranges/goal-range");

            _referenceId = XPathHelper.GetOptNavValue(navigator, "reference-id");
        }
        
        /// <summary>
        /// Writes the XML representation of the CarePlanGoal into
        /// the specified XML writer.
        /// </summary>
        ///
        /// <param name="nodeName">
        /// The name of the outer node for the medical image study series.
        /// </param>
        ///
        /// <param name="writer">
        /// The XML writer into which the CarePlanGoal should be
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
            Validator.ThrowIfStringNullOrEmpty(nodeName, "nodeName");
            Validator.ThrowIfArgumentNull(writer, "writer", "WriteXmlNullWriter");

            Validator.ThrowSerializationIfNull(_name, "CarePlanGoalNameNull");

            writer.WriteStartElement("goal");
            {
                _name.WriteXml("name", writer);
                XmlWriterHelper.WriteOptString(writer, "description", _description);
                XmlWriterHelper.WriteOpt<ApproximateDateTime>(writer, "start-date", _startDate);
                XmlWriterHelper.WriteOpt<ApproximateDateTime>(writer, "end-date", _endDate);
                XmlWriterHelper.WriteOptGuid(writer, "thing-type-version-id", _thingTypeVersionId);
                XmlWriterHelper.WriteOptString(writer, "thing-type-value-xpath", _thingTypeValueXPath);
                XmlWriterHelper.WriteOptString(writer, "thing-type-display-xpath", _thingTypeDisplayXPath);
                XmlWriterHelper.WriteOpt<CodableValue>(writer, "value-unit", _valueUnit);
                XmlWriterHelper.WriteOpt<UnitConversion>(writer, "unit-conversion", _unitConversion);

                XmlWriterHelper.WriteXmlCollection<CarePlanGoalRange>(writer, "goal-ranges", _goalRanges, "goal-range");

                XmlWriterHelper.WriteOptString(writer, "reference-id", _referenceId);
            }

            writer.WriteEndElement();
        }
        
        /// <summary>
        /// Gets or sets name of the goal.
        /// </summary>
        /// 
        /// <remarks>
        /// Example: average blood-glucose for the last seven days
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
                Validator.ThrowIfArgumentNull(value, "Name", "CarePlanGoalNameNull");
                _name = value;
            }
        }
        
        private CodableValue _name;
        
        /// <summary>
        /// Gets or sets description of the goal.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about description the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> is empty or contains only whitespace.
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
                        "CarePlanGoalDateInvalid");
                }
            }
        }        

        /// <summary>
        /// Gets or sets the start date of the goal.
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
        /// Gets or sets the end date of the goal.
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
        /// Gets or sets the version id of the HealthVault type associated with this goal.
        /// </summary>
        /// 
        /// <remarks>
        /// Thing type version id is used to specify which HealthVault data type contains information 
        /// useful to evaluate this goal. 
        /// 
        /// If there is no information about the ThingTypeVersionId, the value should be set to <b>null</b>.
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
        /// Gets or sets XPath expression for the value field associated with this goal in the thing type.
        /// </summary>
        /// 
        /// <remarks>
        /// Thing type value XPath could be used to specify which element in a thing type defined by the thing-type-version-id can be used to find the measurements.
        /// If there is no information about thingTypeValueXPath the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string ThingTypeValueXPath
        {
            get
            {
                return _thingTypeValueXPath;
            }
            
            set
            {
                Validator.ThrowIfStringIsEmptyOrWhitespace(value, "ThingTypeValueXPath");
                _thingTypeValueXPath = value;
            }
        }
        
        private string _thingTypeValueXPath;
        
        /// <summary>
        /// Gets or sets XPath expression for the display field associated with this goal in the thing type.
        /// </summary>
        /// 
        /// <remarks>
        /// Thing type display XPath should point to a "display-value" element in the thing XML for the type defined by the thing-type-version-id.
        /// If there is no information about thingTypeDisplayXPath the value should be set to <b>null</b>.
        /// </remarks>
        ///
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string ThingTypeDisplayXPath
        {
            get
            {
                return _thingTypeDisplayXPath;
            }
            
            set
            {
                Validator.ThrowIfStringIsEmptyOrWhitespace(value, "ThingTypeDisplayXPath");
                _thingTypeDisplayXPath = value;
            }
        }
        
        private string _thingTypeDisplayXPath;
        
        /// <summary>
        /// Gets or sets unit for the goal value.
        /// </summary>
        /// 
        /// <remarks>
        /// If there is no information about valueUnit the value should be set to <b>null</b>.
        /// </remarks>
        ///
        [SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly", Justification = "FXCop thinks that CodableValue is a collection, so it throws this error.")]
        public CodableValue ValueUnit
        {
            get
            {
                return _valueUnit;
            }
            
            set
            {
                _valueUnit = value;
            }
        }
        
        private CodableValue _valueUnit;
        
        /// <summary>
        /// Gets or sets multiplier and offset values used to compute the display value from the measurement value.
        /// </summary>
        /// 
        /// <remarks>
        /// To convert from the measurement units to value units multiply by the multiplier and add the offset.
        /// If there is no information about unitConversion the value should be set to <b>null</b>.
        /// </remarks>
        ///
        public UnitConversion UnitConversion
        {
            get
            {
                return _unitConversion;
            }
            
            set
            {
                _unitConversion = value;
            }
        }
        
        private UnitConversion _unitConversion;
        
        /// <summary>
        /// Gets or sets list of goal ranges.
        /// </summary>
        /// 
        public Collection<CarePlanGoalRange> GoalRanges
        {
            get
            {
                return _goalRanges;
            }

            set
            {
                _goalRanges = value;
            }
        }

        private Collection<CarePlanGoalRange> _goalRanges =
            new Collection<CarePlanGoalRange>();     
        
        /// <summary>
        /// Gets or sets an unique id to distinguish one goal from another.
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
        /// Gets a string representation of the CarePlanGoal.
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of the CarePlanGoal.
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
                    ResourceRetriever.GetResourceString("CarePlanGoalFormat"),
                    _name.Text,
                    _description);
            }

            return result;
        }
    }
}
