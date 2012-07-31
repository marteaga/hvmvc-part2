// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Xml;
using System.Xml.XPath;

using Microsoft.Health;
using Microsoft.Health.ItemTypes;

namespace Microsoft.Health.Events
{
    /// <summary>
    /// A class that contains information about a <see cref="HealthRecordItem" />
    /// that has changed.
    /// </summary>
    public class HealthRecordItemChangedItem
    {
        /// <summary>
        /// The id of the item that has changed.
        /// </summary>
        /// <remarks>
        /// This is equivalent to the id in the <see cref="HealthRecordItem.Key" /> property.
        /// </remarks>
        public Guid Id
        {
            get { return _id; }
            set { _id = value; }
        }
        private Guid _id;

        /// <summary>
        /// The <see cref="HealthRecordItem" /> instance that has changed.
        /// </summary>
        /// <remarks>
        /// <see cref="HealthRecordItemChangedEventArgs.GetItems()" /> must
        /// be called to set this value. 
        /// </remarks>
        public HealthRecordItem Item
        {
            get { return _item; }
            set { _item = value; }
        }
        private HealthRecordItem _item;
    }
}
