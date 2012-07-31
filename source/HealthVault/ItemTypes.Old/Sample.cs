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
    /// Represents a single sample of a measurement or data point.
    /// </summary>
    /// 
    /// <remarks>
    /// A sample is a single measurement within a larger activity. For instance,
    /// the a single heart rate reading during an aerobic activity.
    /// </remarks>
    /// 
    public class Sample : HealthRecordItemData
    {
        /// <summary>
        /// Creates a new instance of the <see cref="Sample"/> class with no value.
        /// </summary>
        /// 
        public Sample()
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="Sample"/> class with the 
        /// specified time offset.
        /// </summary>
        /// 
        /// <param name="timeOffset">
        /// The time offset in seconds from the start of the sample set.
        /// </param>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="timeOffset"/> parameter is less than zero.
        /// </exception>
        /// 
        public Sample(double timeOffset)
        {
            this.TimeOffset = timeOffset;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="Sample"/> class with the 
        /// specified time offset and value.
        /// </summary>
        /// 
        /// <param name="timeOffset">
        /// The time offset in seconds from the start of the sample set.
        /// </param>
        /// 
        /// <param name="value">
        /// The value.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="timeOffset"/> parameter is less than zero.
        /// </exception>
        /// 
        public Sample(double timeOffset, string value)
        {
            this.TimeOffset = timeOffset;
            this.Value = value;
        }

        /// <summary> 
        /// Populates the data for the measurement from the XML.
        /// </summary>
        /// 
        /// <param name="navigator"> 
        /// The XML node representing the measurement.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="navigator"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);

            _timeOffset =
                navigator.SelectSingleNode("time-offset").ValueAsDouble;

            _note = XPathHelper.GetOptNavValue(navigator, "note");

            _value = 
                XPathHelper.GetOptNavValue(
                    navigator,
                    "value");
        }

        /// <summary> 
        /// Writes the sample to the specified XML writer.
        /// </summary>
        /// 
        /// <param name="nodeName">
        /// The name of the outer element for the sample.
        /// </param>
        /// 
        /// <param name="writer"> 
        /// The XmlWriter to write the sample to.
        /// </param>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="nodeName"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="writer"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void WriteXml(string nodeName, XmlWriter writer)
        {
            Validator.ThrowIfStringNullOrEmpty(nodeName, "nodeName");
            Validator.ThrowIfWriterNull(writer);

            writer.WriteStartElement(nodeName);

            writer.WriteElementString(
                "time-offset",
                XmlConvert.ToString(_timeOffset));

            if (!String.IsNullOrEmpty(_note))
            {
                writer.WriteElementString("note", _note);
            }

            XmlWriterHelper.WriteOptString(
                writer,
                "value",
                this.Value);

            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the time offset in seconds from the start of the
        /// sample set.
        /// </summary>
        /// 
        /// <value>
        /// A number representing the time offset, in seconds.
        /// </value>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="value"/> parameter is negative.
        /// </exception>
        /// 
        public double TimeOffset
        {
            get { return _timeOffset; }
            set
            {
                Validator.ThrowArgumentOutOfRangeIf(value < 0.0, "TimeOffset", "SampleTimeOffsetNegative");
                _timeOffset = value;
            }
        }
        private double _timeOffset;

        /// <summary>
        /// Gets or sets a description of the sample.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the description.
        /// </value>
        /// 
        /// <remarks>
        /// If the value is <b>null</b>, the note will not be saved.
        /// </remarks>
        /// 
        /// <exception cref="ArgumentException">
        /// If <paramref name="value"/> contains only whitespace.
        /// </exception>
        /// 
        public string Note
        {
            get { return _note; }
            set 
            {
                Validator.ThrowIfStringIsWhitespace(value, "Note");
                _note = value;
            }
        }
        private string _note;

        /// <summary>
        /// Gets or sets the value of the sample.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the value of the sample.
        /// </value>
        /// 
        /// <remarks>
        /// A sample value can consist of a single integer or a double, as for
        /// a heart rate sample or speed sample. It can also be a more complex
        /// value such as longitude and latitude for position. The format of the
        /// value depends on the sample type.
        /// </remarks>
        /// 
        public string Value
        {
            get { return _value; }
            set { _value = value; }
        }
        private string _value;
    }
}
