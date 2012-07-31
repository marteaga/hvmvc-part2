// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.Globalization;
using System.Runtime.Serialization;
using System.Security.Cryptography.X509Certificates;
using System.Security.Permissions;

namespace Microsoft.Health
{
    /// <summary>
    /// Helper class that allows the SDK to throw the appropriate
    /// HealthServiceException based on the status code returned by 
    /// HealthVault.
    /// </summary>
    /// 
    internal static class HealthServiceExceptionHelper
    {
        /// <summary>
        /// Helper method that allows the SDK to throw the appropriate
        /// HealthServiceException based on the status code returned by 
        /// HealthVault.
        /// </summary>
        /// 
        /// <param name="errorCodeId">
        /// The integer status code returned by HealthVault representing the 
        /// error which occurred.
        ///</param>
        /// <param name="error">
        /// Information about an error that occurred while processing
        /// the request.
        /// </param>
        /// 
        internal static HealthServiceException GetHealthServiceException(int errorCodeId,
            HealthServiceResponseError error)
        {
            HealthServiceException e = null;
            HealthServiceStatusCode errorCode =
                HealthServiceStatusCodeManager.GetStatusCode(errorCodeId);

            if (errorCode != HealthServiceStatusCode.UnmappedError)
            {
                e = GetHealthServiceException(errorCode, error);
            }
            else
            {
                e = new HealthServiceException(errorCodeId, error);
            }

            return e;
        }


        /// <summary>
        /// Helper method that allows the SDK to throw the appropriate
        /// HealthServiceException based on the status code indicating the error
        /// type.
        /// </summary>
        /// 
        /// <param name="errorCode">
        /// The status code representing the error which occurred.
        /// </param>
        /// 
        /// <param name="error">
        /// Information about an error that occurred while processing
        /// the request.
        /// </param>
        /// 
        internal static HealthServiceException GetHealthServiceException(
            HealthServiceStatusCode errorCode,
            HealthServiceResponseError error)
        {
            HealthServiceException e = null;
            switch (errorCode)
            {
                case HealthServiceStatusCode.CredentialTokenExpired:
                    e = new HealthServiceCredentialTokenExpiredException(error);
                    break;
                case HealthServiceStatusCode.AuthenticatedSessionTokenExpired:
                    e = new HealthServiceAuthenticatedSessionTokenExpiredException(error);
                    break;
                case HealthServiceStatusCode.InvalidPerson:
                    e = new HealthServiceInvalidPersonException(error);
                    break;
                case HealthServiceStatusCode.InvalidRecord:
                    e = new HealthServiceInvalidRecordException(error);
                    break;
                case HealthServiceStatusCode.AccessDenied:
                    e = new HealthServiceAccessDeniedException(error);
                    break;
                case HealthServiceStatusCode.InvalidApplicationAuthorization:
                    e = new HealthServiceInvalidApplicationAuthorizationException(error);
                    break;
                case HealthServiceStatusCode.DuplicateCredentialFound:
                    e = new HealthServiceApplicationDuplicateCredentialException(error);
                    break;
                case HealthServiceStatusCode.MailAddressMalformed:
                    e = new HealthServiceMailAddressMalformedException(error);
                    break;
                case HealthServiceStatusCode.PasswordNotStrong:
                    e = new HealthServicePasswordNotStrongException(error);
                    break;
                case HealthServiceStatusCode.RecordQuotaExceeded:
                    e = new HealthServiceRecordQuotaExceededException(error);
                    break;
                case HealthServiceStatusCode.OtherDataItemSizeLimitExceeded :
                    e = new HealthServiceOtherDataSizeLimitExceededException(error);
                    break;
                default:
                    e = new HealthServiceException(errorCode, error);
                    break;
            }
            return e;
        }
    }


}
