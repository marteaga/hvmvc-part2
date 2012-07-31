using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.Health.Authentication
{
    /// <summary>
    /// SafeHandle implemetation for crypto key handles.
    /// </summary>
    internal class SafeCryptoKeyHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeCryptoKeyHandle()
            : base(true)
        {
        }

        private SafeCryptoKeyHandle(IntPtr key)
            : base(true)
        {
            base.SetHandle(key);
        }

        /// <summary>
        /// Executes the code required to free the handle.
        /// </summary>
        /// 
        /// <returns>
        /// true if the handle is released successfully; otherwise, in the event 
        /// of a catastrophic failure, false. In this case, it generates a ReleaseHandleFailed 
        /// Managed Debugging Assistant.
        /// </returns>
        protected override bool ReleaseHandle()
        {
            return UnsafeNativeMethods.CryptDestroyKey(base.handle);
        }

        internal static SafeCryptoKeyHandle ZeroHandle
        {
            get
            {
                SafeCryptoKeyHandle handle = new SafeCryptoKeyHandle(IntPtr.Zero);
                return handle;
            }
        }
    }
}

