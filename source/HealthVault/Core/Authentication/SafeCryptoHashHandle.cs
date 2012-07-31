using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Microsoft.Health.Authentication
{
    /// <summary>
    /// SafeHandle implementation for crypto hash handles.
    /// </summary>
    internal class SafeCryptoHashHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeCryptoHashHandle()
            : base(true)
        {
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
            return UnsafeNativeMethods.CryptDestroyHash(base.handle);
        }
    }
}

