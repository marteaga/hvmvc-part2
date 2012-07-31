// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

namespace Microsoft.Health.Web
{
    /// <summary>
    /// Indicates the type of the audit action template being used for a
    /// <see cref="HealthRecordItemDataGrid"/>.
    /// </summary>
    /// 
    public enum TemplateType
    {
        /// <summary>
        /// The template is being used as a header.
        /// </summary>
        /// 
        Header,

        /// <summary>
        /// The template is being used for an item.
        /// </summary>
        /// 
        Item
    }

}
