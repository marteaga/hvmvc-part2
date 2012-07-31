// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Xml;
using System.Xml.XPath;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;


namespace Microsoft.Health
{
    /// <summary>
    /// Supported certificate types.
    /// </summary>
    /// 
    public enum CertificateType
    {
        /// <summary>
        /// The HealthRecordItem is not signed.
        /// </summary>
        /// 
        None = 0,

        /// <summary>
        /// Unable to determine the type of the certificate used to sign the HealthRecordItem.
        /// </summary>
        /// 
        Unknown = 1,

        /// <summary>
        /// Matches <see cref="System.Security.Cryptography.X509Certificates.X509Certificate2"/>.
        /// </summary>
        /// 
        X509Certificate = 2
    };
}

