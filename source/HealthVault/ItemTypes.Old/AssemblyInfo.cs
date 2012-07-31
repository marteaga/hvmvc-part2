// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System.Reflection;
using System.Security;
using System.Security.Permissions;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

[assembly: ReliabilityContractAttribute(Consistency.MayCorruptAppDomain, Cer.MayFail)]
[assembly: AssemblyTitle("Microsoft.Health.ItemTypes.Old")]
[assembly: AssemblyDescription("Microsoft HealthVault Item Types Assembly for types that have been replaced with newer versions")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, Flags = 0)]
