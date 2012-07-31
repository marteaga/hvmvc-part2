// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Health.Certificate
{
    /// <summary>
    /// Utility class.
    /// </summary>
    internal static class Util
    {
        ///	<summary>
        ///	Get the formatted string of the last error message
        ///	</summary>
        internal static string GetLastErrorMessage()
        {
            return new Win32Exception(Marshal.GetLastWin32Error()).Message;
        }
    }
}
