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
    /// Represents a set of samples within a larger activity or reading.
    /// </summary>
    /// 
    /// <remarks>
    /// An example of a sample set is a set of heart rate readings during an 
    /// aerobic activity.
    /// </remarks>
    /// 
    public class SampleSet : HealthRecordItemData
    {
        /// <summary>
        /// Creates a new instance of the <see cref="SampleSet"/> class with no value.
        /// </summary>
        /// 
        public SampleSet()
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="SampleSet"/> class with 
        /// the specified start time for the set.
        /// </summary>
        /// 
        /// <param name="baseTime">
        /// The time when the samples in the set started.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="baseTime"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public SampleSet(HealthServiceDateTime baseTime)
        {
            this.BaseTime = baseTime;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="SampleSet"/> class with 
        /// the specified start time for the set.
        /// </summary>
        /// 
        /// <param name="baseTime">
        /// The time when the samples in the set started.
        /// </param>
        /// 
        /// <param name="sampleUnit">
        /// Text description of the unit of measure for the sample
        /// values in this set.
        /// </param>
        /// 
        /// <param name="sampleUnitCode">
        /// Vocabulary code for the unit of measure for the sample
        /// values in this set.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="baseTime"/> or <paramref name="sampleUnitCode"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="sampleUnit"/> parameter is <b>null</b> or empty.
        /// </exception>
        /// 
        public SampleSet(
            HealthServiceDateTime baseTime,
            String sampleUnit,
            CodableValue sampleUnitCode)
        {
            this.BaseTime = baseTime;
            this.SampleUnit = sampleUnit;
            this.SampleUnitCode = sampleUnitCode;
        }

        /// <summary> 
        /// Populates the data for the sample set from the XML.
        /// </summary>
        /// 
        /// <param name="navigator"> 
        /// The XML node representing the sample set.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="navigator"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);

            // Delay parsing until a property is requested
            _sampleSetNav = navigator;
        }

        private void DelayParseXml()
        {

            _baseTime = new HealthServiceDateTime();
            _baseTime.ParseXml(
                _sampleSetNav.SelectSingleNode("base-time"));

            _sampleUnit =
                XPathHelper.GetOptNavValue(
                    _sampleSetNav,
                    "sample-unit");

            _sampleUnitCode =
                XPathHelper.GetOptNavValue<CodableValue>(
                    _sampleSetNav,
                    "sample-unit-code");

            XPathNodeIterator sampleIterator =
                _sampleSetNav.Select("sample");

            _samples = new Collection<Sample>();
            foreach (XPathNavigator sampleNav in sampleIterator)
            {
                Sample sample = new Sample();
                sample.ParseXml(sampleNav);

                _samples.Add(sample);
            }
            _isXmlParsed = true;
        }

        private void EnsureParsed()
        {
            if (!_isXmlParsed && _sampleSetNav != null)
            {
                DelayParseXml();
            }
        }

        /// <summary> 
        /// Writes the sample set to the specified XML writer.
        /// </summary>
        /// 
        /// <param name="nodeName">
        /// The name of the outer element for the sample set.
        /// </param>
        /// 
        /// <param name="writer"> 
        /// The XmlWriter to write the sample set to.
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
        /// <exception cref="HealthRecordItemSerializationException">
        /// The <see cref="BaseTime"/>, <see cref="SampleUnit"/>, or <see cref="SampleUnitCode"/> 
        /// property has not been set.
        /// </exception>
        /// 
        public override void WriteXml(string nodeName, XmlWriter writer)
        {
            Validator.ThrowIfStringNullOrEmpty(nodeName, "nodeName");
            Validator.ThrowIfWriterNull(writer);

            EnsureParsed();

            Validator.ThrowSerializationIfNull(_baseTime, "SampleSetBaseTimeNotSpecified");
            Validator.ThrowSerializationIf(String.IsNullOrEmpty(_sampleUnit), "SampleSetUnitNotSpecified");
            Validator.ThrowSerializationIfNull(_sampleUnitCode, "SampleSetUnitCodeNotSpecified");

            writer.WriteStartElement(nodeName);

            _baseTime.WriteXml("base-time", writer);

            XmlWriterHelper.WriteOptString(writer, "sample-unit", _sampleUnit);

            XmlWriterHelper.WriteOpt<CodableValue>(
                writer,
                "sample-unit-code",
                _sampleUnitCode);

            for (int index = 0; index < _samples.Count; ++index)
            {
                _samples[index].WriteXml("sample", writer);
            }

            writer.WriteEndElement();
        }

        private XPathNavigator _sampleSetNav;
        private bool _isXmlParsed;

        /// <summary>
        /// Gets or sets the time when the sample set started recording samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="HealthServiceDateTime"/> representing the starting 
        /// time for sample recording.
        /// </value>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public HealthServiceDateTime BaseTime
        {
            get 
            {
                EnsureParsed();
                return _baseTime; 
            }
            set
            {
                Validator.ThrowIfArgumentNull(value, "BaseTime", "SampleSetBaseTimeMandatory");
                _baseTime = value;
            }
        }
        private HealthServiceDateTime _baseTime;

        /// <summary>
        /// Gets a text description of the unit of measure for the sample
        /// values in this set.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the description.
        /// </value>
        /// 
        /// <exception cref="ArgumentException">
        /// The <paramref name="value"/> parameter is <b>null</b>, empty, or contains only whitespace.
        /// </exception>
        /// 
        public string SampleUnit
        {
            get 
            {
                EnsureParsed();
                return _sampleUnit;
            }
            set 
            {
                Validator.ThrowIfStringNullOrEmpty(value, "SampleUnit");
                Validator.ThrowIfStringIsWhitespace(value, "SampleUnit");
                _sampleUnit = value;
            }
        }
        private string _sampleUnit;

        /// <summary>
        /// Gets the vocabulary code for the unit of measure for the sample
        /// values in this set.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="CodableValue"/> representing the vocabulary 
        /// code.
        /// </value>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public CodableValue SampleUnitCode
        {
            get 
            {
                EnsureParsed();
                return _sampleUnitCode;
            }
            set 
            {
                Validator.ThrowIfArgumentNull(value, "SampleUnitCode", "SampleSetUnitCodeMandatory");
                _sampleUnitCode = value;
            }
        }
        private CodableValue _sampleUnitCode;

        /// <summary>
        /// Gets a collection containing the samples in the set.
        /// </summary>
        /// 
        /// <value>
        /// A collection of samples.
        /// </value>
        /// 
        public Collection<Sample> Samples
        {
            get 
            {
                EnsureParsed();
                return _samples;
            }
        }
        private Collection<Sample> _samples = new Collection<Sample>();
    }
}
