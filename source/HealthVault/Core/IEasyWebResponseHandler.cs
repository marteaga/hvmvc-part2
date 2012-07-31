// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Text;
using System.Threading;
using System.Xml;

namespace Microsoft.Health
{
    /// <summary> 
    /// handler to implement custom response handling 
    /// </summary>
    /// 
    internal interface IEasyWebResponseHandler
    {
        /// <summary>
        /// the callback 
        /// </summary>
        /// 
        /// <param name="stream"></param>
        /// 
        void HandleResponseStream(Stream stream);
    }
}

