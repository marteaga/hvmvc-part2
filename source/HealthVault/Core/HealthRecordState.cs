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
using Microsoft.Health.Web;
using Microsoft.Health.Web.Authentication;

namespace Microsoft.Health
{
    /// <summary>
    /// The state of a record.
    /// </summary>
    ///
    public enum HealthRecordState
    {

        /// <summary>
        /// An unknown state was returned from the server.
        /// </summary>
        /// 
        Unknown = 0,    
        
        /// <summary>
        /// Active. All is well.
        /// </summary>
        ///
        Active,

        /// <summary>
        /// The record can be viewed, but not modified.
        /// </summary>
        ///
        ReadOnly,

        /// <summary>
        /// The record is inaccessible and was disabled by the system.
        /// </summary>
        ///
        Suspended,

        /// <summary>
        /// The record is inaccessible and was deleted by the user.
        /// </summary>
        ///
        Deleted,

    }


}
