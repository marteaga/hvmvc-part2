// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Xsl;
using System.Xml.XPath;

namespace Microsoft.Health
{
    /// <summary>
    /// Represents the version information for a health record item type.
    /// </summary>
    public class HealthRecordItemTypeVersionInfo
    {
        private HealthRecordItemTypeVersionInfo() { }

        internal HealthRecordItemTypeVersionInfo(
            Guid versionTypeId,
            string versionName,
            int versionSequence)
        {
            _versionTypeId = versionTypeId;
            _versionName = versionName;
            _versionSequence = versionSequence;
        }

        /// <summary>
        /// Gets the unique identifier for the versioned health record item type.
        /// </summary>
        public Guid VersionTypeId
        {
            get { return _versionTypeId; }
        }
        private Guid _versionTypeId;

        /// <summary>
        /// Gets the name for this version of the health record item type.
        /// </summary>
        public string Name
        {
            get { return _versionName; }
        }
        private String _versionName;

        /// <summary>
        /// Gets the sequence number for the health record item type version.
        /// </summary>
        /// <remarks>
        /// The sequence number starts at one and is incremented for each new version
        /// of the type that gets added.
        /// </remarks>
        public int VersionSequence
        {
            get { return _versionSequence; }
        }
        private int _versionSequence;
    }
}
