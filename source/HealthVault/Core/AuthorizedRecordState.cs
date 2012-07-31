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
using Microsoft.Health;
using Microsoft.Health.Authentication;

namespace Microsoft.Health
{
    /// <summary>
    /// Defines the state of a HealthVault record authorization.
    /// </summary>
    /// 
    public enum AuthorizedRecordState
    {
        /// <summary>
        /// The record authorization is active.
        /// </summary>
        Active = 100,

        /// <summary>
        /// The record authorization is pending activation.
        /// </summary>
        ActivationPending = 200,

        /// <summary>
        /// The record authorization is rejected for activation.
        /// </summary>
        ActivationRejected = 300,
    }
}
