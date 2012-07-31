// Copyright(c) Microsoft Corporation.
// This content is subject to the Microsoft Reference Source License,
// see http://www.microsoft.com/resources/sharedsource/licensingbasics/sharedsourcelicenses.mspx.
// All other rights reserved.


using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.Health.Certificate
{
    /// <summary>
    /// Generates a new HealthVault application certificate.
    /// This certificate is typically used by HealthVaultClientApplication
    /// </summary>
    internal class ApplicationCertificate : IDisposable
    {
        #region constants
        /// <summary>
        /// Client application certificates will be prefixed by HVClient
        /// </summary>
        private const string CertSubjectPrefix = "HVClientApp-";

        /// <summary>
        /// Default number of years for certificate validity
        /// </summary>
        private const short NumberOfYears = 31;
        #endregion 

        #region private variables
        private KeyContainerHandle _keyContainer;
        private KeyHandle _key;
        private CertificateHandle _nativeCert;
        #endregion

        #region Constructor

        /// <summary>
        /// Creates an instance of ApplicationCertificate
        /// This will create a new GUID which will be used for naming 
        /// the certificate
        /// </summary>
        public ApplicationCertificate()
            : this(Guid.NewGuid())
        {
        }

        /// <summary>
        /// Creates an instance of ApplicationCertificate
        /// </summary>
        /// <param name="applicationID">
        /// Application ID. Used to associate the certificate and application
        /// </param>
        public ApplicationCertificate(Guid applicationID)
            : this(applicationID, false)
        {
        }

        ~ApplicationCertificate()
        {
            Dispose(false);
        }

        /// <summary>
        /// Creates an instance of ApplicationCertificate
        /// </summary>
        /// <param name="applicationID">
        /// Application ID. Used to associate the certificate and application.
        /// </param>
        /// <param name="alwaysCreate">
        ///     Specify to always create the certificate.
        /// </param>
        public ApplicationCertificate(Guid applicationID, bool alwaysCreate)
            : this(applicationID, alwaysCreate, StoreLocation.CurrentUser)
        {
        }


        /// <summary>
        /// Generate an X509 cert that works with the HealthVault SDK
        /// </summary>
        /// <param name="applicationID"></param>
        /// <param name="alwaysCreate"></param>
        /// <param name="storeLocation"></param>
        public ApplicationCertificate(Guid applicationID, bool alwaysCreate, StoreLocation storeLocation)
        {
            using (CertificateStore store = new CertificateStore(storeLocation))
            {
                if (!alwaysCreate)
                {
                    //
                    // Use an existing cert, if any
                    //
                    _certificate = store[applicationID];
                }

                if (_certificate == null)
                {
                    CreateCert(applicationID, NumberOfYears);
                    AddNativeCertToStore();
                    
                }
            }
        }

        #endregion

        #region public properties
        /// <summary>
        /// Returns the native certificate
        /// </summary>
        internal X509Certificate2 Certificate
        {
            get
            {
                return _certificate;
            }

        }

        private X509Certificate2 _certificate;

        #endregion 


        #region static methods

        /// <summary>
        ///     Make subject for certificate
        /// </summary>
        /// <param name="appID"></param>
        /// <returns></returns>
        internal static string MakeCertSubject(Guid appID)
        {
            return "CN=" + MakeCertName(appID);
        }

        /// <summary>
        ///     Create name of certificate from appID
        /// </summary>
        /// <param name="appID"></param>
        /// <returns></returns>
        internal static string MakeCertName(Guid appID)
        {
            return ApplicationCertificate.CertSubjectPrefix + appID.ToString("D");
        }
        #endregion

        #region Private Methods
        /// <summary>
        /// Creates a certificate 
        /// </summary>
        /// <param name="appID"></param>
        /// <param name="numberOfYears"></param>
        /// 
        private void CreateCert(Guid appID, short numberOfYears)
        {
            
            // convert the times to SystemTime structures
            NativeMethods.SystemTime beginTime = new NativeMethods.SystemTime(DateTime.Now);
            NativeMethods.SystemTime expireTime = new NativeMethods.SystemTime(DateTime.Now);
            expireTime.wYear += numberOfYears;

            // convert the name into a X500 name
            CertificateName certName = new CertificateName(MakeCertSubject(appID));
                       
            GenerateKeys(appID);

            // create the certificate
            using (CryptoApiBlob nameBlob = certName.GetCryptoApiBlob())
            {
                _nativeCert = NativeMethods.CertCreateSelfSignCertificate(_keyContainer,
                                                     nameBlob,
                                                     NativeMethods.SelfSignFlags.None,
                                                     IntPtr.Zero,
                                                     IntPtr.Zero,
                                                     ref beginTime,
                                                     ref expireTime,
                                                     IntPtr.Zero);

                if (_nativeCert.IsInvalid)
                {
                    _nativeCert.Dispose();
                    _nativeCert = null;
                    throw new CryptographicException(String.Format(
                        CultureInfo.InvariantCulture,
                        ResourceRetriever.GetResourceString(
                            "ApplicationCertificateUnableToCreateCert"),
                        Util.GetLastErrorMessage()));
                }
                else
                {
                    // okay to use DangerousGetHandle here as handle is valid and 
                    // used for creation of the certificate only. No reference is added
                    //
                    _certificate = new X509Certificate2(_nativeCert.DangerousGetHandle());
                }
            }            
        }

        /// <summary>
        /// Adds the certificate to the store
        /// </summary>
        private  void AddNativeCertToStore()
        {
            IntPtr marshalStoreName = IntPtr.Zero;
            CertificateStoreHandle store = null;
            CertificateHandle addedCert = null;

            try
            {  
                marshalStoreName = Marshal.StringToHGlobalUni("My");

                store = NativeMethods.CertOpenStore(
                        new IntPtr(NativeMethods.CERT_STORE_PROV_SYSTEM),
                        0,                            
                        IntPtr.Zero,
                        (int)NativeMethods.CertSystemStoreFlags.CurrentUser,
                        marshalStoreName);

                // add the certificate to the store                           
                if (!NativeMethods.CertAddCertificateContextToStore(
                        store,
                        _nativeCert,
                        NativeMethods.AddDisposition.ReplaceExisting,
                        out addedCert))
                {
                    throw new CryptographicException(String.Format(
                        CultureInfo.InvariantCulture,
                        ResourceRetriever.GetResourceString(
                            "ApplicationCertificateUnableToAddCertToStore"), 
                            Util.GetLastErrorMessage()));
                }
                
                
            }
            finally
            {
                if (marshalStoreName != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(marshalStoreName);
                }
                if (store != null)
                {
                    store.Dispose();
                }
                if (addedCert != null)
                {
                    addedCert.Dispose();
                }                
            }
        }

        private static string GetKeyContainerName(Guid appId)
        {
            return "SelfSignedCert" + appId.ToString();
        }

        /// <summary>
        /// 	Generate a key pair to be used in the certificate
        /// </summary>
        private void GenerateKeys(Guid appId)
        {
            // generate the key container to put the key in
            if (!NativeMethods.CryptAcquireContext(out _keyContainer,
                                     GetKeyContainerName(appId),
                                     null,
                                     NativeMethods.ProviderType.RsaFull,
                                     NativeMethods.ContextFlags.NewKeySet | NativeMethods.ContextFlags.Silent))
            {
                Win32Exception win32Exception = new Win32Exception(Marshal.GetLastWin32Error());

                throw new CryptographicException(
                        ResourceRetriever.GetResourceString(
                            "ApplicationCertificateUnableToAcquireContext"),
                            win32Exception.Message);
            }

            // generate the key
            if (!NativeMethods.CryptGenKey(_keyContainer,
                            NativeMethods.AlgorithmType.Signature,
                            NativeMethods.KeyFlags.Exportable,
                            out _key))
            {
                Win32Exception win32Exception = new Win32Exception(Marshal.GetLastWin32Error());

                throw new CryptographicException(
                    ResourceRetriever.GetResourceString(
                        "ApplicationCertificateUnableToGenerateKey"),
                    win32Exception.Message);
            }
        }

        public static void DeleteKeyContainer(Guid appId)
        {
            KeyContainerHandle keyContainer = null;

                // Remove the key container...
            try
            {
                NativeMethods.CryptAcquireContext(out keyContainer,
                                             GetKeyContainerName(appId),
                                             null,
                                             NativeMethods.ProviderType.RsaFull,
                                             NativeMethods.ContextFlags.DeleteKeySet);
            }
            finally
            {
                if (keyContainer != null)
                {
                    keyContainer.Dispose();
                }
            }
        }
        #endregion


        #region Dispose
        /// <summary>
        /// 	Clean up the contained managed classes that need disposing. 
        /// </summary>
        /// <param name="disposing">true if called from Dispose, false if from the finalizer</param>
        /// <remarks>
        /// This class does not need a finalizer as the managed classes that wrap that native OS 
        /// resources for certificates have finalizers. Howerver, there may be a need for a subclass to
        /// introduce a finalizer, so Dispose is properly implemented.
        /// </remarks>
        protected virtual void Dispose(bool disposing)
        {

            if (disposing)
            {
                if (_nativeCert != null)
                {
                    _nativeCert.Dispose();                 
                }

                if (_key != null)
                {
                    _key.Dispose();
                }

                if (_keyContainer != null)
                {
                    _keyContainer.Dispose();
                    _keyContainer = null;
                }
            }
            _nativeCert = null;
            _key = null;
        }

        /// <summary>
        /// 	
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            
            // Use SupressFinalize in case a subclass of this type implements a finalizer.
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
