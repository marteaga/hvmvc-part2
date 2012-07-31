// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml.Serialization;


namespace Microsoft.Health
{
    internal class HealthVaultPlatformTrace
    {
        private static TraceSource s_traceSource = new TraceSource("HealthVaultTraceSource");

        internal static void LogRequest(Byte[] utf8Bytes)
        {
            if (LoggingEnabled)
            {
                s_traceSource.TraceInformation(
                        Encoding.UTF8.GetString(utf8Bytes));
            }
        }

        internal static void LogRequest(string request)
        {
            s_traceSource.TraceInformation(request);
        }

        internal static bool LoggingEnabled
        {
            get 
            {
                bool result = s_traceSource.Switch.ShouldTrace(TraceEventType.Information);
                return result;
 
            }
        }

        internal static void LogResponse(string responseString)
        {
            s_traceSource.TraceInformation(responseString);
        }

        internal static void LogResponse(HealthServiceResponseData response)
        {
            string responseString = String.Empty;
            string infoXml = 
                (response.InfoNavigator != null) 
                    ? response.InfoNavigator.OuterXml : String.Empty;

             if (response.Error == null)
            {
                responseString = 
                    String.Join(
                        String.Empty,
                            new string[] 
                            { 
                                "Code:",
                                response.Code.ToString(),
                                "|Info:",
                                infoXml 
                            });

            }
            else
            {
                responseString = 
                    String.Join(String.Empty,
                        new string[] 
                        { 
                            "Code:",
                            response.Code.ToString(),
                            "|Error:",
                            response.Error.ToString(),
                            "|Info:",
                            infoXml 
                        });
            }
            s_traceSource.TraceInformation(responseString);
        }

        internal static void LogCertLoading(
            string logEntryFormat,
            params object[] parameters)
        {
            if (s_traceSource.Switch.ShouldTrace(TraceEventType.Verbose))
            {
                s_traceSource.TraceInformation(logEntryFormat, parameters);
            }
        }
    }
}
