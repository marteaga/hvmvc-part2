// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Microsoft.Health;
using Microsoft.Health.Authentication;

namespace Microsoft.Health
{
    /// <summary>
    /// The public HealthVault methods that are available for applications to call.
    /// </summary>
    /// 
    /// Note, the numeric value is not important. These values don't map directly to the
    /// platform method enum values.
    /// 
    public enum HealthVaultMethods
    {
        /// <summary>
        /// Creates an application session token for use with the HealthVault service.
        /// </summary>
        /// 
        CreateAuthenticatedSessionToken,

        /// <summary>
        /// Removes a saved open query.
        /// </summary>
        /// 
        DeleteOpenQuery,

        /// <summary>
        /// Gets information about the registered application including name, description,
        /// authorization rules, and callback url.
        /// </summary>
        /// 
        GetApplicationInfo,

        /// <summary>
        /// Saves application specific information for the logged in user.
        /// </summary>
        /// 
        GetApplicationSettings,

        /// <summary>
        /// Gets all the records that the user has authorized the application use.
        /// </summary>
        /// 
        GetAuthorizedRecords,

        /// <summary>
        /// Gets existing saved open queries.
        /// </summary>
        /// 
        GetOpenQueryInfo,

        /// <summary>
        /// Gets information about the logged in user.
        /// </summary>
        /// 
        GetPersonInfo,

        /// <summary>
        /// Gets generic service information about the HealthVault service.
        /// </summary>
        /// 
        GetServiceDefinition,

        /// <summary>
        /// Gets data from a HealthVault record.
        /// </summary>
        /// 
        GetThings,

        /// <summary>
        /// Gets information, including schemas, about the data types that can be stored in a
        /// health record.
        /// </summary>
        /// 
        GetThingType,

        /// <summary>
        /// Gets information about clinical and other vocabularies that HealthVault supports.
        /// </summary>
        /// 
        GetVocabulary,

        /// <summary>
        /// Adds or updates data in a health record.
        /// </summary>
        /// 
        PutThings,

        /// <summary>
        /// Gets the permissions that the application and user have to a health record.
        /// </summary>
        /// 
        QueryPermissions,

        /// <summary>
        /// Removes data from a health record.
        /// </summary>
        /// 
        RemoveThings,

        /// <summary>
        /// Creates a saved open query.
        /// </summary>
        /// 
        SaveOpenQuery,

        /// <summary>
        /// Sends an SMTP message on behalf of the logged in user.
        /// </summary>
        /// 
        SendInsecureMessage,

        /// <summary>
        /// Sends an SMTP message on behalf of the application.
        /// </summary>
        /// 
        SendInsecureMessageFromApplication,

        /// <summary>
        /// Sets application specific data for the user.
        /// </summary>
        /// 
        SetApplicationSettings,
    }
}
