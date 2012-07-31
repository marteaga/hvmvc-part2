// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.

using System;

namespace Microsoft.Health
{
    /// <summary>
    /// Encapsulates information about when changes occur to the collection of 
    /// <see cref="HealthRecordItem"/>s occur in a <see cref="HealthRecordAccessor"/>.
    /// </summary>
    public class HealthRecordUpdateInfo 
    {
        /// <summary>
        /// Create a new instance of the <see cref="HealthRecordUpdateInfo"/> class for testing purposes. 
        /// </summary>
        protected HealthRecordUpdateInfo()
        {
        }

        internal HealthRecordUpdateInfo(Guid recordId, DateTime lastUpdateDate)
        {
            _recordId = recordId;
            _lastUpdateDate = lastUpdateDate;
        }

        /// <summary>
        /// Gets or sets the ID of the <see cref="HealthRecordAccessor"/> updated.
        /// </summary>
        public Guid RecordId
        {
            get { return _recordId; }
            protected set { _recordId = value; }
        }
        private Guid _recordId;

        /// <summary>
        /// Gets or sets the timestamp when an addition, deletion or update occured to the 
        /// <see cref="HealthRecordItem"/>s in the <see cref="HealthRecordAccessor"/> 
        /// </summary>
        public DateTime LastUpdateDate
        {
            get { return _lastUpdateDate; }
            protected set { _lastUpdateDate = value; }
        }       
        private DateTime _lastUpdateDate;
    }
}