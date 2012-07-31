// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System.Reflection;
using System.Security.Permissions;
using System.Runtime.CompilerServices;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;

[assembly: ReliabilityContractAttribute(Consistency.MayCorruptAppDomain, Cer.MayFail)]
[assembly: AssemblyTitle("Microsoft.Health")]
[assembly: AssemblyDescription("Microsoft HealthVault SDK Assembly")]
[assembly: SecurityPermission(SecurityAction.RequestMinimum, Flags = 0)]
[assembly: InternalsVisibleTo(@"Microsoft.Health.Web")]
[assembly: InternalsVisibleTo(@"Microsoft.Health.ItemTypes")]
[assembly: InternalsVisibleTo(@"Microsoft.Health.ItemTypes.Old")]



