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
    /// Represents data about a single lap within an aerobic session.
    /// </summary>
    /// 
    /// <remarks>
    /// A lap is a grouping of data based on an interval of time.
    /// </remarks>
    /// 
    public class LapSession : HealthRecordItemData
    {
        /// <summary>
        /// Creates a new instance of the <see cref="LapSession"/> class 
        /// with default values.
        /// </summary>
        /// 
        public LapSession()
            : base()
        {
        }

        /// <summary> 
        /// Populates the data for the lap from the XML.
        /// </summary>
        /// 
        /// <param name="navigator"> 
        /// The XML node representing the lap.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="navigator"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);

            _name =
                XPathHelper.GetOptNavValue(navigator, "name");

            _secondsIntoSession =
                XPathHelper.GetOptNavValueAsDouble(
                    navigator, 
                    "seconds-into-session");

            XPathNavigator nav =
                navigator.SelectSingleNode("lap-session");

            if (nav != null)
            {
                _lapData = new AerobicData();
                _lapData.ParseXml(nav);
            }
        }

        /// <summary> 
        /// Writes the lap to the specified XML writer.
        /// </summary>
        /// 
        /// <param name="nodeName">
        /// The name of the outer element for the lap.
        /// </param>
        /// 
        /// <param name="writer"> 
        /// The XmlWriter to write the lap data to.
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

            if (!String.IsNullOrEmpty(_name))
            {
                writer.WriteElementString("name", _name);
            }

            XmlWriterHelper.WriteOptDouble(
                writer,
                "seconds-into-session",
                _secondsIntoSession);

            if (_lapData != null)
            {
                _lapData.WriteXml("lap-session", writer);
            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the name of the lap.
        /// </summary>
        /// 
        /// <value>
        /// A string representing the lap name.
        /// </value>
        /// 
        /// <remarks>
        /// This is a user- or device-defined name for the lap data.
        /// </remarks>
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
        /// Gets or sets the seconds into the session of when then lap started.
        /// </summary>
        /// 
        /// <value>
        /// A number representing the seconds.
        /// </value>
        /// 
        /// <exception cref="ArgumentOutOfRangeException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public double? SecondsIntoSession
        {
            get { return _secondsIntoSession; }
            set
            {
                Validator.ThrowArgumentOutOfRangeIf(
                    value != null && value < 0.0,
                    "SecondsIntoSession",
                    "LapSessionSecondsIntoSessionNonNegative");
                _secondsIntoSession = value;
            }

        }
        private double? _secondsIntoSession;

        /// <summary>
        /// Gets or sets the summary of aerobic data for the lap.
        /// </summary>
        /// 
        /// <value>
        /// An <see cref="AerobicData"/> value representing the summary.
        /// </value>
        /// 
        public AerobicData LapData
        {
            get { return _lapData; }
            set { _lapData = value; }
        }
        private AerobicData _lapData;
    }
}
