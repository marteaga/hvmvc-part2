// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Runtime.Serialization;
using System.Security.Permissions;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Health.ItemTypes;
using System.IO;

namespace Microsoft.Health
{        
    internal class HealthRecordItemTypeHandler
    {
        internal HealthRecordItemTypeHandler(Type thingTypeClass)
        {
            _thingTypeClass = thingTypeClass;
        }

        internal HealthRecordItemTypeHandler(Guid typeId, Type thingTypeClass)
            : this(thingTypeClass)
        {
            _typeId = typeId;
        }

        internal Type ItemTypeClass
        {
            get { return _thingTypeClass; }
        }
        private Type _thingTypeClass;

        internal Guid TypeId
        {
            get { return _typeId; }
        }
        private Guid _typeId= Guid.Empty;
    }
}
