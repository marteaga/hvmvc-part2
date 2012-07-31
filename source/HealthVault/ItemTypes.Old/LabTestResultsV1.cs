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

using Microsoft.Health.ItemTypes;

namespace Microsoft.Health.ItemTypes.Old
{
    /// <summary>
    /// A series of lab test results.
    /// </summary>
    /// 
    public class LabTestResultsV1 : HealthRecordItem
    {
        /// <summary>
        /// Initialize a new instance of the <see cref="LabTestResults"/> 
        /// class with default values.
        /// </summary>
        /// 
        public LabTestResultsV1()
            : base(TypeId)
        {
        }

        /// <summary>
        /// Initialize a new instance of the <see cref="LabTestResults"/> 
        /// class with mandatory parameters.
        /// </summary>
        /// 
        /// <param name="labGroups">Lab groups is a set of lab results.</param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="labGroups"/> parameter is <b> null </b>.
        /// </exception>
        /// 
        public LabTestResultsV1(IEnumerable<LabTestResultGroupV1> labGroups)
            : base(TypeId)
        {
            Validator.ThrowIfArgumentNull(labGroups, "labGroups", "LabTestResultsLabGroupMandatory");

            foreach (LabTestResultGroupV1 labGroup in labGroups)
            {
                _labGroup.Add(labGroup);
            }
        }

        /// <summary>
        /// Retrieves the unique identifier for the item type.
        /// </summary>
        /// 
        public new static readonly Guid TypeId =
            new Guid("F57746AF-9631-49DC-944E-2C92BEE0D1E9");

        /// <summary>
        /// Populates this <see cref="LabTestResults"/> instance from the data in the XML. 
        /// </summary>
        /// 
        /// <param name="typeSpecificXml">
        /// The XML to get the lab test results data from.
        /// </param>
        /// 
        /// <exception cref="InvalidOperationException">
        /// If the first node in <paramref name="typeSpecificXml"/> is not
        /// a lab test results node.
        /// </exception>
        /// 
        protected override void ParseXml(IXPathNavigable typeSpecificXml)
        {
            XPathNavigator itemNav =
                typeSpecificXml.CreateNavigator().SelectSingleNode("lab-test-results");

            Validator.ThrowInvalidIfNull(itemNav, "LabTestResultsUnexpectedNode");

            // when 
            _when =
                XPathHelper.GetOptNavValue<ApproximateDateTime>(itemNav, "when");

            // lab-group
            XPathNodeIterator labGroupIterator =
                itemNav.Select("lab-group");
            _labGroup = new Collection<LabTestResultGroupV1>();
            foreach (XPathNavigator labGroupNav in labGroupIterator)
            {
                LabTestResultGroupV1 labTestResultGroupV1 = new LabTestResultGroupV1();
                labTestResultGroupV1.ParseXml(labGroupNav);
                _labGroup.Add(labTestResultGroupV1);
            }

            // ordered-by
            _orderedBy =
                XPathHelper.GetOptNavValue<Organization>(itemNav, "ordered-by");

        }

        /// <summary>
        /// Writes the lab test results data to the specified XmlWriter.
        /// </summary> 
        /// 
        /// <param name="writer">
        /// The XmlWriter to write the lab test results data to.
        /// </param>
        /// 
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="writer"/> parameter is <b>null</b>.
        /// </exception>
        /// 
        /// <exception cref="HealthRecordItemSerializationException">
        /// If <see cref="Groups"/> is <b>null</b> or empty.
        /// </exception> 
        /// 
        public override void WriteXml(XmlWriter writer)
        {
            Validator.ThrowIfWriterNull(writer);
            Validator.ThrowSerializationIf(
                _labGroup == null || _labGroup.Count == 0,
                "LabTestResultsLabGroupNotSet");

            // <lab-test-results>
            writer.WriteStartElement("lab-test-results");

            // when
            XmlWriterHelper.WriteOpt<ApproximateDateTime>(
                writer,
                "when",
                _when);

            // lab-group
            for (int index = 0; index < _labGroup.Count; ++index)
            {
                _labGroup[index].WriteXml("lab-group", writer);
            }

            // ordered-by
            XmlWriterHelper.WriteOpt<Organization>(
                writer,
                "ordered-by",
                _orderedBy);

            // </lab-test-results>
            writer.WriteEndElement();
        }

        /// <summary>
        /// Gets or sets the date and time of the lab tests results.  
        /// </summary>
        /// 
        /// <remarks>
        /// The date and time should be set to <b> null </b> if they are 
        /// unknown. 
        /// </remarks>
        /// 
        public ApproximateDateTime When
        {
            get { return _when; }
            set { _when = value; }
        }
        private ApproximateDateTime _when;

        /// <summary>
        /// Gets a set of lab results.
        /// </summary>
        /// 
        public Collection<LabTestResultGroupV1> Groups
        {
            get { return _labGroup; }
        }
        private Collection<LabTestResultGroupV1> _labGroup =
            new Collection<LabTestResultGroupV1>();

        /// <summary>
        /// Gets or sets the information about the organization which
        /// ordered the lab tests.
        /// </summary>
        /// 
        /// <remarks>
        /// It should be set to <b> null</b> if it is unknown. 
        /// </remarks>
        /// 
        public Organization OrderedBy
        {
            get { return _orderedBy; }
            set { _orderedBy = value; }
        }
        private Organization _orderedBy;

        /// <summary>
        /// Gets a string representation of the lab test results item.
        /// </summary> 
        ///
        /// <returns>
        /// A string representation of the lab test results item.
        /// </returns>
        /// 
        public override string ToString()
        {
            StringBuilder result = new StringBuilder(200);

            for (int index = 0; index < _labGroup.Count; ++index)
            {
                if (_labGroup[index].GroupName != null)
                {
                    if (!String.IsNullOrEmpty(_labGroup[index].GroupName.Text))
                    {
                        if (index > 0)
                        {
                            result.AppendFormat(
                                ResourceRetriever.GetResourceString(
                                    "ListFormat"),
                                _labGroup[index].GroupName.Text.ToString());
                        }
                        else
                        {
                            result.Append(_labGroup[index].GroupName.Text.ToString());
                        }
                    }
                }
            }
            return result.ToString();
        }
    }
}
