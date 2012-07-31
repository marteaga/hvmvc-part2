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
    /// Represents a health record item type that encapsulates an aerobic session.
    /// </summary>
    /// <remarks>
    /// Note: Please use the new exercise type instead of this type.
    /// </remarks>
    /// 
    public class AerobicSession : HealthRecordItem
    {
        /// <summary>
        /// Creates a new instance of the <see cref="AerobicSession"/> class with default values.
        /// </summary>
        /// 
        /// <remarks>
        /// The item is not added to the health record until the
        /// <see cref="Microsoft.Health.HealthRecordAccessor.NewItem(HealthRecordItem)"/> 
        /// method is called.
        /// </remarks>
        /// 
        public AerobicSession()
            : base(TypeId)
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="AerobicSession"/> class with 
        /// the specified date and time.
        /// </summary>
        /// 
        /// <param name="when">
        /// The date/time when the aerobic session occurred.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="when"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public AerobicSession(HealthServiceDateTime when)
            : base(TypeId)
        {
            this.When = when;
        }

        /// <summary>
        /// Creates a new instance of the <see cref="AerobicSession"/> class with 
        /// the specified date and time and summary.
        /// </summary>
        /// 
        /// <param name="when">
        /// The date/time when the aerobic session occurred.
        /// </param>
        /// 
        /// <param name="session">
        /// The summary information about the aerobic session.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="when"/> or <paramref name="session"/> parameter 
        /// is <b>null</b>.
        /// </exception>
        /// 
        public AerobicSession(HealthServiceDateTime when, AerobicData session)
            : base(TypeId)
        {
            this.When = when;
            this.Session = session;
        }

        /// <summary>
        /// The unique identifier for the item type.
        /// </summary>
        /// 
        public new static readonly Guid TypeId = 
            new Guid("90dbf000-fc55-4b92-b4a1-da45c36ad8bb");

        /// <summary>
        /// Populates this AerobicSession instance from the data in the XML.
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the aerobic session data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// The first node in <paramref name="typeSpecificXml"/> is not
        /// an aerobic-session node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator aerobicSessionNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode(
                    "aerobic-session");

            Validator.ThrowInvalidIfNull(aerobicSessionNav, "AerobicSessionUnexpectedNode");

            _when = new HealthServiceDateTime();
            _when.ParseXml(aerobicSessionNav.SelectSingleNode("when"));

            _session = new AerobicData();
            _session.ParseXml(aerobicSessionNav.SelectSingleNode("session"));

            XPathNavigator samplesNav =
                aerobicSessionNav.SelectSingleNode("session-samples");
            if (samplesNav != null)
            {
                _sessionSamples = new AerobicSessionSamples();
                _sessionSamples.ParseXml(samplesNav);
            }

            XPathNodeIterator lapsIterator =
                aerobicSessionNav.Select("lap-session");

            _lapSessions = new Collection<LapSession>();
            foreach (XPathNavigator lapNav in lapsIterator)
            {
                LapSession lap = new LapSession();
                lap.ParseXml(lapNav);

                _lapSessions.Add(lap);
            }
        }


        /// <summary>
        /// Writes the aerobic session data to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the aerobic session data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b>null</b>.
        /// </exception>
        /// 
        public override void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);

            // <aerobic-session>
            writer.WriteStartElement("aerobic-session");

            // <when>
            _when.WriteXml("when", writer);

            _session.WriteXml("session", writer);

            if (_sessionSamples != null)
            {
                _sessionSamples.WriteXml("session-samples", writer);
            }

            for (int index = 0; index < _lapSessions.Count; ++index)
            {
                _lapSessions[index].WriteXml("lap-session", writer);
            }

            // </aerobic-session>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the date/time when the aerobic session occurred.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="HealthServiceDateTime"/> instance. 
        /// The value defaults to the current year, month, and day.
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
        /// Gets or sets the aerobic session data.
        /// </summary>
        /// 
        /// <value>
        /// An <see cref="AerobicData"/> instance containing the summary 
        /// information for the session.
        /// </value>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="value"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public AerobicData Session
        {
            get { return _session; }
            set 
            {
                Validator.ThrowIfArgumentNull(value, "Session", "AerobicSessionMandatory");
                _session = value;
            }
        }
        private AerobicData _session = new AerobicData();

        /// <summary>
        /// Gets or sets the session samples.
        /// </summary>
        /// 
        /// <value>
        /// An <see cref="AerobicSessionSamples"/> instance.
        /// </value>
        /// 
        public AerobicSessionSamples SessionSamples
        {
            get { return _sessionSamples; }
            set { _sessionSamples = value; }
        }
        private AerobicSessionSamples _sessionSamples;

        /// <summary>
        /// Gets the lap summary data for the session.
        /// </summary>
        /// 
        /// <value>
        /// A collection of items representing summary data for a lap in
        /// the session.
        /// </value>
        /// 
        public Collection<LapSession> LapSessions
        {
            get { return _lapSessions; }
        }
        private Collection<LapSession> _lapSessions = 
            new Collection<LapSession>();

        /// <summary>
        /// Gets a string representation of the aerobic session item.
        /// </summary>
        /// 
        /// <returns>
        /// A string representation of the aerobic session item.
        /// </returns>
        /// 
        public override string ToString()
        {
            return Session.ToString();
        }
    }

}
