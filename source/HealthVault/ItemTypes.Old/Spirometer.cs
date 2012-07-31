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
    /// Represents a health record item that encapsulates a single reading 
    /// from a spirometer.
    /// </summary>
    /// <remarks>
    /// Note: Please use the peak flow type instead of this type.
    /// </remarks>
    /// 
    public class Spirometer : HealthRecordItem
    {
        /// <summary>
        /// Creates a new instance of the <see cref="Spirometer"/> class with default values.
        /// </summary>
        /// 
        /// <remarks>
        /// The item is not added to the health record until the
        /// <see cref="Microsoft.Health.HealthRecordAccessor.NewItem(HealthRecordItem)"/> method 
        /// is called.
        /// </remarks>
        /// 
        public Spirometer()
            : base(TypeId)
        {
        }

        /// <summary>
        /// Creates a new instance of the <see cref="Spirometer"/> class 
        /// specifying the mandatory values.
        /// </summary>
        /// 
        /// <param name="when">
        /// The date and time when the spirometer reading occurred.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="when"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        public Spirometer(HealthServiceDateTime when) : base (TypeId)
        {
            this.When = when;
        }

        /// <summary>
        /// Retrieves the unique identifier for the item type.
        /// </summary>
        /// 
        public new static readonly Guid TypeId =
            new Guid("921588d1-27bf-423c-8e55-650d2fedb3e0");

        /// <summary>
        /// Populates this <see cref="Spirometer"/> instance from the data in the XML.
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the spirometer data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// The first node in the <paramref name="typeSpecificXml"/> parameter 
        /// is not a spirometer node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator spirometerNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode(
                    "spirometer");

            Validator.ThrowInvalidIfNull(spirometerNav, "SpirometerUnexpectedNode");

            _when = new HealthServiceDateTime();
            _when.ParseXml(spirometerNav.SelectSingleNode("when"));

            _forcedExpiratoryVolume = 
                XPathHelper.GetOptNavValue<FlowMeasurement>(
                    spirometerNav,
                    "fev1");

            _peakExpiratoryFlow =
                XPathHelper.GetOptNavValue<FlowMeasurement>(
                    spirometerNav,
                    "pef");

            XPathNodeIterator warningsIterator =
                spirometerNav.Select("warning");

            foreach (XPathNavigator warningNav in warningsIterator)
            {
                _warnings.Add(warningNav.Value);
            }

            XPathNodeIterator problemsIterator =
                spirometerNav.Select("problem");

            foreach (XPathNavigator problemNav in problemsIterator)
            {
                _problems.Add(problemNav.Value);
            }

            XPathNavigator fevOverFvcNav =
                spirometerNav.SelectSingleNode("FEVoverFVC");

            if (fevOverFvcNav != null)
            {
                _fevOverFvc = fevOverFvcNav.ValueAsDouble;
            }

            XPathNavigator fef25to75Nav =
                spirometerNav.SelectSingleNode("FEF25to75");

            if (fef25to75Nav != null)
            {
                _fef25to75 = fef25to75Nav.ValueAsDouble;
            }

            XPathNavigator fef25to50Nav =
                spirometerNav.SelectSingleNode("FEF25to50");

            if (fef25to50Nav != null)
            {
                _fef25to50 = fef25to50Nav.ValueAsDouble;
            }

            XPathNavigator fif25to75Nav =
                spirometerNav.SelectSingleNode("FIF25to75");

            if (fif25to75Nav != null)
            {
                _fif25to75 = fif25to75Nav.ValueAsDouble;
            }

            XPathNavigator fif25to50Nav =
                spirometerNav.SelectSingleNode("FIF25to50");

            if (fif25to50Nav != null)
            {
                _fif25to50 = fif25to50Nav.ValueAsDouble;
            }

            XPathNavigator fetNav =
                spirometerNav.SelectSingleNode("FET");

            if (fetNav != null)
            {
                _fet = fetNav.ValueAsDouble;
            }

            _svc =
                XPathHelper.GetOptNavValue<VolumeMeasurement>(
                    spirometerNav,
                    "SVC");

            _tv =
                XPathHelper.GetOptNavValue<VolumeMeasurement>(
                    spirometerNav,
                    "TV");

            _mvv =
                XPathHelper.GetOptNavValue<FlowMeasurement>(
                    spirometerNav,
                    "MVV");
        }

        /// <summary>
        /// Writes the spirometer data to the specified XmlWriter.
        /// </summary>
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the spirometer use data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthRecordItemSerializationException">
        /// If <see cref="When"/> is <b>null</b>.
        /// </exception>
        /// 
        public override void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);
            Validator.ThrowSerializationIfNull(_when, "SpirometerWhenNotSet");

            // <spirometer>
            writer.WriteStartElement("spirometer");

            // <when>
            _when.WriteXml("when", writer);


            XmlWriterHelper.WriteOpt<FlowMeasurement>(
                writer,
                "fev1",
                ForcedExpiratoryVolume);


            XmlWriterHelper.WriteOpt<FlowMeasurement>(
                writer,
                "pef",
                PeakExpiratoryFlow); 
            
            foreach (string warning in _warnings)
            {
                writer.WriteElementString("warning", warning);
            }

            foreach (string problem in _problems)
            {
                writer.WriteElementString("problem", problem);
            }

            if (FevOverFvc != null)
            {
                writer.WriteElementString(
                    "FEVoverFVC",
                    XmlConvert.ToString((double)FevOverFvc));
            }


            if (Fef25to75 != null)
            {
                writer.WriteElementString(
                    "FEF25to75",
                    XmlConvert.ToString((double)Fef25to75));
            }

            if (Fef25to50 != null)
            {
                writer.WriteElementString(
                    "FEF25to50",
                    XmlConvert.ToString((double)Fef25to50));
            }

            if (Fif25to75 != null)
            {
                writer.WriteElementString(
                    "FIF25to75",
                    XmlConvert.ToString((double)Fif25to75));
            }

            if (Fif25to50 != null)
            {
                writer.WriteElementString(
                    "FIF25to50",
                    XmlConvert.ToString((double)Fif25to50));
            }

            if (ForcedExpiratoryTime != null)
            {
                writer.WriteElementString(
                    "FET",
                    XmlConvert.ToString((double)ForcedExpiratoryTime));
            }

            XmlWriterHelper.WriteOpt<VolumeMeasurement>(
                writer,
                "SVC",
                SlowVitalCapacity);

            XmlWriterHelper.WriteOpt<VolumeMeasurement>(
                writer,
                "TV",
                TidalVolume); 

            XmlWriterHelper.WriteOpt<FlowMeasurement>(
                writer,
                "MVV",
                MaxVoluntaryVentilation);

            // </spirometer>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the date and time when the spirometer reading occurred.
        /// </summary>
        /// 
        /// <returns>
        /// A <see cref="HealthServiceDateTime"/> instance representing the date 
        /// and time.
        /// </returns>
        /// 
        /// <remarks>
        /// The value defaults to the current year, month, and day.
        /// </remarks>
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
        /// Gets or sets the forced expiratory volume measured in 
        /// liters per second (L/s).
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the volume.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the forced expiratory volume should not
        /// be stored.
        /// </remarks>
        /// 
        public FlowMeasurement ForcedExpiratoryVolume
        {
            get { return _forcedExpiratoryVolume; }
            set { _forcedExpiratoryVolume = value; }
        }
        private FlowMeasurement _forcedExpiratoryVolume;

        /// <summary>
        /// Gets or sets the peak expiratory flow measured in liters per 
        /// second (L/s).
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the peak flow.
        /// </returns> 
        /// 
        /// <remarks>
        /// Set the value to <b>null</b> if the peak expiratory flow should not
        /// be stored.
        /// </remarks>
        /// 
        public FlowMeasurement PeakExpiratoryFlow
        {
            get { return _peakExpiratoryFlow; }
            set { _peakExpiratoryFlow = value; }
        }
        private FlowMeasurement _peakExpiratoryFlow;

        /// <summary>
        /// Gets a collection of the warnings that occurred during the reading.
        /// </summary>
        /// 
        /// <returns>
        /// A collection of strings representing the warnings.
        /// </returns> 
        /// 
        /// <remarks>
        /// To add a warning, pass a string containing the warning message 
        /// to the Add method of a returned collection.
        /// <br/><br/>
        /// Warnings indicate the reading was not normal. The text of the 
        /// warning tells what is of concern.
        /// </remarks>
        /// 
        public Collection<string> Warnings
        {
            get { return _warnings; }
        }
        private Collection<string> _warnings = new Collection<string>();

        /// <summary>
        /// Gets a collection of the problems that occurred during the reading.
        /// </summary>
        /// 
        /// <returns>
        /// A collection of strings representing the problems.
        /// </returns> 
        /// 
        /// <remarks>
        /// To add a problem, pass a string containing the problem message 
        /// to the Add method of a returned collection.
        /// <br/><br/>
        /// Problems indicate the reading was not normal and indicates an 
        /// action should be taken. The text of the problem tells what is of 
        /// concern.
        /// </remarks>
        /// 
        public Collection<string> Problems
        {
            get { return _problems; }
        }
        private Collection<string> _problems = new Collection<string>();

        /// <summary>
        /// Gets or sets the ratio of the Forced Expiratory Volume (FEV) over
        /// Forced Vital Capacity (FVC).
        /// </summary>
        /// 
        /// <returns>
        /// A collection of strings representing the ratio.
        /// </returns> 
        /// 
        /// <remarks>
        /// In healthy adults, this value should be approximately 75-80%.
        /// </remarks>
        /// 
        public double? FevOverFvc
        {
            get { return _fevOverFvc; }
            set { _fevOverFvc = value; }
        }
        private double? _fevOverFvc;

        /// <summary>
        /// Gets or sets the average flow of air coming out of the lungs 
        /// during the middle (25-75%) portion of the expiration.
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the flow.
        /// </returns>
        /// 
        public double? Fef25to75
        {
            get { return _fef25to75; }
            set { _fef25to75 = value; }
        }
        private double? _fef25to75;

        /// <summary>
        /// Gets or sets the average flow of air coming out of the lungs 
        /// during the middle (25-50%) portion of the expiration.
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the flow.
        /// </returns> 
        /// 
        public double? Fef25to50
        {
            get { return _fef25to50; }
            set { _fef25to50 = value; }
        }
        private double? _fef25to50;

        /// <summary>
        /// Gets or sets the average inspiratory flow 
        /// during the middle (25-75%) portion of inspiration.
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the flow.
        /// </returns> 
        /// 
        public double? Fif25to75
        {
            get { return _fif25to75; }
            set { _fif25to75 = value; }
        }
        private double? _fif25to75;

        /// <summary>
        /// Gets or sets the average inspiratory flow 
        /// during the middle (25-50%) portion of inspiration.
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the flow.
        /// </returns> 
        /// 
        public double? Fif25to50
        {
            get { return _fif25to50; }
            set { _fif25to50 = value; }
        }
        private double? _fif25to50;

        /// <summary>
        /// Gets or sets the length of expiration in seconds.
        /// </summary>
        /// 
        public double? ForcedExpiratoryTime
        {
            get { return _fet; }
            set { _fet = value; }
        }
        private double? _fet;

        /// <summary>
        /// Gets or sets the capacity of the lungs during expiration or
        /// inspiration, measured in liters (L).
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the capacity in liters (L).
        /// </returns> 
        /// 
        public VolumeMeasurement SlowVitalCapacity
        {
            get { return _svc; }
            set { _svc = value; }
        }
        private VolumeMeasurement _svc;

        /// <summary>
        /// Gets or sets the tidal volume, measured in liters (L).
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the volume measured in liters (L).
        /// </returns> 
        /// 
        /// <remarks>
        /// This is the specific volume of air that is drawn
        /// into and then expired out of the lungs.
        /// </remarks>
        ///
        public VolumeMeasurement TidalVolume
        {
            get { return _tv; }
            set { _tv = value; }
        }
        private VolumeMeasurement _tv;

        /// <summary>
        /// Gets or sets the maximum voluntary ventilation (MVV) measured
        /// in liters per second (L/s).
        /// </summary>
        /// 
        /// <returns>
        /// A number representing the ventilation measured in liters per 
        /// second (L/s).
        /// </returns> 
        /// 
        /// <remarks>
        /// For this test, patients inspire and expire
        /// into the spirometer over and over again as fast 
        /// as they can, for at least 12 seconds.
        /// </remarks>
        /// 
        public FlowMeasurement MaxVoluntaryVentilation
        {
            get { return _mvv; }
            set { _mvv = value; }
        }
        private FlowMeasurement _mvv;

        /// <summary>
        /// Gets a string representation of the spirometer reading.
        /// </summary>
        /// 
        /// <returns>
        /// A string representing the vault of the spirometer reading.
        /// </returns>
        /// 
        public override string ToString()
        {
            StringBuilder result = new StringBuilder(100);

            if (ForcedExpiratoryVolume != null)
            {
                result.Append(ForcedExpiratoryVolume.ToString());
            }
            if (PeakExpiratoryFlow != null)
            {
                if (result.Length > 0)
                {
                    result.AppendFormat(
                        ResourceRetriever.GetResourceString(
                            "ListSeparator"));
                }
                result.Append(PeakExpiratoryFlow.ToString());
            }
            if (Warnings.Count > 0)
            {
                if (result.Length > 0)
                {
                    result.AppendFormat(
                        ResourceRetriever.GetResourceString(
                            "ListSeparator"));
                }
                for (int index = 0; index < Warnings.Count; ++index)
                {
                    if (index > 0)
                    {
                        result.AppendFormat(
                            ResourceRetriever.GetResourceString(
                                "ListSeparator"));
                    }
                    result.Append(Warnings[index]);
                }
            }
            if (Problems.Count > 0)
            {
                if (result.Length > 0)
                {
                    result.AppendFormat(
                        ResourceRetriever.GetResourceString(
                            "ListSeparator"));
                }
                for (int index = 0; index < Problems.Count; ++index)
                {
                    if (index > 0)
                    {
                        result.AppendFormat(
                            ResourceRetriever.GetResourceString(
                                "ListSeparator"));
                    }
                    result.Append(Problems[index]);
                }
            }
            return result.ToString();
        }
    }
}
