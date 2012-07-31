// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.XPath;

namespace Microsoft.Health.ItemTypes.Old
{
    /// <summary>
    /// Defines a method for registering all the health record item types with the
    /// <see cref="Microsoft.Health.ItemTypeManager"/> that are in this assembly.
    /// </summary>
    /// 
    public static class ItemTypeOldRegistrar
    {
        /// <summary>
        /// Registers all the health record item types in this assembly with the 
        /// <see cref="Microsoft.Health.ItemTypeManager"/>.
        /// </summary>
        /// 
        public static void RegisterAssemblyHealthRecordItemTypes()
        {
            foreach (ItemTypeManager.DefaultTypeHandler typeHandler in _defaultTypeHandlers)
            {
                ItemTypeManager.RegisterTypeHandler(typeHandler.TypeId, typeHandler.Type, true);
            }
        }

        private static ItemTypeManager.DefaultTypeHandler[] _defaultTypeHandlers =
            new ItemTypeManager.DefaultTypeHandler[]
            {
                new ItemTypeManager.DefaultTypeHandler(AerobicSession.TypeId, typeof(AerobicSession)),
                new ItemTypeManager.DefaultTypeHandler(EncounterV1.TypeId, typeof(EncounterV1)),
                new ItemTypeManager.DefaultTypeHandler(FamilyHistoryV1.TypeId, typeof(FamilyHistoryV1)),
                new ItemTypeManager.DefaultTypeHandler(ImmunizationV1.TypeId, typeof(ImmunizationV1)),
                new ItemTypeManager.DefaultTypeHandler(LabTestResultsV1.TypeId, typeof(LabTestResultsV1)),
                new ItemTypeManager.DefaultTypeHandler(MedicationV1.TypeId, typeof(MedicationV1)),
                new ItemTypeManager.DefaultTypeHandler(ProcedureV1.TypeId, typeof(ProcedureV1)),
                new ItemTypeManager.DefaultTypeHandler(Spirometer.TypeId, typeof(Spirometer)),
            };

    }
}
