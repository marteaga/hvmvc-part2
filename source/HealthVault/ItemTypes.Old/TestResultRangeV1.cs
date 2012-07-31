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
    /// A test result range defines the minimum and the maximum of a specific test result value.
    /// </summary>
    ///
    public class TestResultRangeV1 : HealthRecordItemData
    {
        /// <summary>
        /// Initialize a new instance of the <see cref="TestResultRange"/> 
        /// class with default values.
        /// </summary>
        /// 
        /// <remarks>
        /// Each test result can contain multiple ranges that are useful 
        /// to interpret the result value. Examples include reference range 
        /// and therapeutic range.
        /// </remarks>
        /// 
        public TestResultRangeV1()
        {
        }

        /// <summary>
        /// Initialize a new instance of the <see cref="TestResultRange"/> 
        /// class with mandatory parameters.
        /// </summary>
        /// 
        /// <param name="type"> 
        /// Type is the type of a test result.
        /// </param>
        /// 
        /// <param name="range"> 
        /// Range is values of minimum and maximum of a test result.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="range"/> or <paramref name="type"/> is <b> null </b>.
        /// </exception>
        /// 
        public TestResultRangeV1(CodableValue type,DoubleRange range)
        {
            RangeType = type;
            Range = range;
        }

        /// <summary>
        /// Populates this <see cref="TestResultRange"/> instance from the data in the XML. 
        /// </summary>
        /// 
        /// <param name="navigator">
        /// The XML to get the test result range data from.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The first node in <paramref name="navigator"/> is <b>null</b>.
        /// </exception>
        ///
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);

            // type
            _rangeType = new CodableValue();
            _rangeType.ParseXml(navigator.SelectSingleNode("type"));

            // range
            _range = new DoubleRange();
            _range.ParseXml(navigator.SelectSingleNode("range"));
        }

        /// <summary>
        /// Writes the test result range data to the specified XmlWriter.
        /// </summary> 
        /// 
        /// <param name="nodeName">
        /// The name of the node to write XML.
        /// </param>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the test result range data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="nodeName"/> is <b> null </b> or empty.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b> null </b>.
        /// </exception>
        ///
        /// <exception cref="HealthRecordItemSerializationException">
        /// If <see cref="Type"> or </see><see cref="Range"/> is <b> null </b>.
        /// </exception> 
        /// 
        public override void WriteXml(string nodeName, XmlWriter writer)
        {
            Validator.ThrowIfStringNullOrEmpty(nodeName, "nodeName");
            Validator.ThrowIfWriterNull(writer);
            Validator.ThrowSerializationIfNull(_rangeType, "TestResultRangeRangeTypeNotSet");
            Validator.ThrowSerializationIfNull(_range, "TestResultRangeRangeNotSet");

            // <test-result-range>
            writer.WriteStartElement(nodeName);

            // type
            _rangeType.WriteXml("type", writer);
         
            // range
            _range.WriteXml("range",writer);

            // </test-result-range>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the range of the test result.
        /// </summary>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If value is <b>null</b>.
        /// </exception>
        /// 
        public DoubleRange Range
        {
            get { return _range;}
            set
            {
                Validator.ThrowIfArgumentNull(value, "Range", "TestResultRangeRangeNotSet");
                _range =  value;
            }
        }
        private DoubleRange _range;

        /// <summary>
        /// Gets or sets the type of the range.  
        /// </summary>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If value is <b>null</b>.
        /// </exception>
        /// 
        public CodableValue RangeType
        {
            get { return _rangeType;}
            set
            {
                Validator.ThrowIfArgumentNull(value, "RangeType", "TestResultRangeRangeTypeNotSet");
                _rangeType =  value;
            }
        }
        private CodableValue _rangeType;

        /// <summary>
        /// Gets a string representation of the test result range item.
        /// </summary> 
        ///
        /// <returns>
        /// A string representation of the test result range item.
        /// </returns>
        ///
        public override string ToString()
        {
            return
                String.Format(
                    ResourceRetriever.GetResourceString(
                        "TestResultRangeToStringFormat"),
                    _rangeType.ToString(),
                    _range.ToString());
        }
    }
}
