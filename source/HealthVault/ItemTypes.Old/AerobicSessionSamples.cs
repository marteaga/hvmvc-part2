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
    /// Contains the various sample sets that can be collected during aerobic
    /// activity.
    /// </summary>
    /// 
    public class AerobicSessionSamples : HealthRecordItemData
    {
        /// <summary>
        /// Creates a new instance of the <see cref="AerobicSessionSamples"/> class with 
        /// default values.
        /// </summary>
        /// 
        public AerobicSessionSamples()
        {
        }


        /// <summary> 
        /// Populates the data for the aerobic session samples from the XML.
        /// </summary>
        /// 
        /// <param name="navigator"> 
        /// The XML node representing the aerobic session samples.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="navigator"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public override void ParseXml(XPathNavigator navigator)
        {
            Validator.ThrowIfNavigatorNull(navigator);

            XPathNavigator setNav =
                navigator.SelectSingleNode("heartrate-samples");
            if (setNav != null)
            {
                _hrSamples = new SampleSet();
                _hrSamples.ParseXml(setNav);
            }

            setNav =
                navigator.SelectSingleNode("distance-samples");
            if (setNav != null)
            {
                _distanceSamples = new SampleSet();
                _distanceSamples.ParseXml(setNav);
            }

            setNav =
                navigator.SelectSingleNode("speed-samples");
            if (setNav != null)
            {
                _speedSamples = new SampleSet();
                _speedSamples.ParseXml(setNav);
            }

            setNav =
                navigator.SelectSingleNode("pace-samples");
            if (setNav != null)
            {
                _paceSamples = new SampleSet();
                _paceSamples.ParseXml(setNav);
            }


            setNav =
                navigator.SelectSingleNode("power-samples");
            if (setNav != null)
            {
                _powerSamples = new SampleSet();
                _powerSamples.ParseXml(setNav);
            }


            setNav =
                navigator.SelectSingleNode("cadence-samples");
            if (setNav != null)
            {
                _cadenceSamples = new SampleSet();
                _cadenceSamples.ParseXml(setNav);
            }

            setNav =
                navigator.SelectSingleNode("temperature-samples");
            if (setNav != null)
            {
                _temperatureSamples = new SampleSet();
                _temperatureSamples.ParseXml(setNav);
            }

            setNav =
                navigator.SelectSingleNode("altitude-samples");
            if (setNav != null)
            {
                _altitudeSamples = new SampleSet();
                _altitudeSamples.ParseXml(setNav);
            }


            setNav =
                navigator.SelectSingleNode("air-pressure-samples");
            if (setNav != null)
            {
                _airPressureSamples = new SampleSet();
                _airPressureSamples.ParseXml(setNav);
            }

            _numberOfStepsSamples = 
                XPathHelper.GetOptNavValue<SampleSet>(navigator, "number-of-steps-samples");

            _numberOfAerobicStepsSamples =
                XPathHelper.GetOptNavValue<SampleSet>(navigator, "number-of-aerobic-steps-samples");

            _aerobicStepMinutesSamples =
                XPathHelper.GetOptNavValue<SampleSet>(navigator, "aerobic-step-minutes-samples");
        }

        /// <summary> 
        /// Writes the aerobic session samples to the specified XML writer.
        /// </summary>
        /// 
        /// <param name="nodeName">
        /// The name of the outer element for the aerobic session samples.
        /// </param>
        /// 
        /// <param name="writer"> 
        /// The XmlWriter to write the aerobic session samples to.
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

            if (_hrSamples != null && _hrSamples.Samples.Count > 0)
            {
                _hrSamples.WriteXml("heartrate-samples", writer);
            }

            if (_distanceSamples != null && _distanceSamples.Samples.Count > 0)
            {
                _distanceSamples.WriteXml("distance-samples", writer);
            }

            if (_speedSamples != null && _speedSamples.Samples.Count > 0)
            {
                _speedSamples.WriteXml("speed-samples", writer);
            }

            if (_paceSamples != null && _paceSamples.Samples.Count > 0)
            {
                _paceSamples.WriteXml("pace-samples", writer);
            }

            if (_powerSamples != null && _powerSamples.Samples.Count > 0)
            {
                _powerSamples.WriteXml("power-samples", writer);
            }

            if (_cadenceSamples != null && _cadenceSamples.Samples.Count > 0)
            {
                _cadenceSamples.WriteXml("cadence-samples", writer);
            }

            if (_temperatureSamples != null && _temperatureSamples.Samples.Count > 0)
            {
                _temperatureSamples.WriteXml("temperature-samples", writer);
            }

            if (_altitudeSamples != null && _altitudeSamples.Samples.Count > 0)
            {
                _altitudeSamples.WriteXml("altitude-samples", writer);
            }

            if (_airPressureSamples != null && _airPressureSamples.Samples.Count > 0)
            {
                _airPressureSamples.WriteXml("air-pressure-samples", writer);
            }

            if (_numberOfStepsSamples != null && _numberOfStepsSamples.Samples.Count > 0)
            {
                _numberOfStepsSamples.WriteXml("number-of-steps-samples", writer);
            }

            if (_numberOfAerobicStepsSamples != null && _numberOfAerobicStepsSamples.Samples.Count > 0)
            {
                _numberOfAerobicStepsSamples.WriteXml("number-of-aerobic-steps-samples", writer);
            }

            if (_aerobicStepMinutesSamples != null && _aerobicStepMinutesSamples.Samples.Count > 0)
            {
                _aerobicStepMinutesSamples.WriteXml("aerobic-step-minutes-samples", writer);
            }

            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the heart rate samples.
        /// </summary>
        /// 
        public SampleSet HeartRateSamples
        {
            get { return _hrSamples; }
            set { _hrSamples = value; }
        }
        private SampleSet _hrSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the distance samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet DistanceSamples
        {
            get { return _distanceSamples; }
            set { _distanceSamples = value; }
        }
        private SampleSet _distanceSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the speed samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet SpeedSamples
        {
            get { return _speedSamples; }
            set { _speedSamples = value; }
        }
        private SampleSet _speedSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the pace samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet PaceSamples
        {
            get { return _paceSamples; }
            set { _paceSamples = value; }
        }
        private SampleSet _paceSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the power samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet PowerSamples
        {
            get { return _powerSamples; }
            set { _powerSamples = value; }
        }
        private SampleSet _powerSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the cadence samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet CadenceSamples
        {
            get { return _cadenceSamples; }
            set { _cadenceSamples = value; }
        }
        private SampleSet _cadenceSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the temperature samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet TemperatureSamples
        {
            get { return _temperatureSamples; }
            set { _temperatureSamples = value; }
        }
        private SampleSet _temperatureSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the altitude samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet AltitudeSamples
        {
            get { return _altitudeSamples; }
            set { _altitudeSamples = value; }
        }
        private SampleSet _altitudeSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the air pressure samples.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet AirPressureSamples
        {
            get { return _airPressureSamples; }
            set { _airPressureSamples = value; }
        }
        private SampleSet _airPressureSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the number of steps sample.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet NumberOfStepsSamples
        {
            get { return _numberOfStepsSamples; }
            set { _numberOfStepsSamples = value; }
        }
        private SampleSet _numberOfStepsSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the number of aerobic steps sample.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet NumberOfAerobicStepsSamples
        {
            get { return _numberOfAerobicStepsSamples; }
            set { _numberOfAerobicStepsSamples = value; }
        }
        private SampleSet _numberOfAerobicStepsSamples = new SampleSet();

        /// <summary>
        /// Gets or sets the number of aerobic step minutes sample.
        /// </summary>
        /// 
        /// <value>
        /// A <see cref="SampleSet"/> instance representing the samples.
        /// </value>
        /// 
        public SampleSet AerobicStepMinutesSamples
        {
            get { return _aerobicStepMinutesSamples; }
            set { _aerobicStepMinutesSamples = value; }
        }
        private SampleSet _aerobicStepMinutesSamples = new SampleSet();
    }
}
