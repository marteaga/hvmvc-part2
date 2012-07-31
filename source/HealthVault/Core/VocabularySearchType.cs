// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Health.Authentication;

namespace Microsoft.Health
{
    /// <summary>
    /// Defines the types of search operations that can be performed on
    /// HealthVault vocabularies.
    /// </summary>
    /// 
    public enum VocabularySearchType
    {
        /// <summary>
        /// Does a prefix search where matching strings are ones that <b>begin</b>
        /// with the search string.         
        /// </summary>
        /// 
        Prefix = 0,

        /// <summary>
        /// Does a contains search where matching strings are ones that <b>contain</b>
        /// the search string.
        /// </summary>
        /// 
        Contains = 1,

        /// <summary>
        /// Does a full text search for the search string.
        /// </summary>
        /// 
        FullText = 2,
    }
}

