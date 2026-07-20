using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace MegaBasterd
{
    // A refusal carries a short fixed reason and never a path: the caller turns
    // any failure into one fixed console warning, and a Win32 message would
    // otherwise smuggle the log path (which may hold an account or a secret)
    // into stderr.
    public class SecureLogRefusal : Exception
    {
        public SecureLogRefusal(string reason) : base(reason) { }
    }

    public class SecureLogOpen
    {
        public SafeFileHandle Handle;
        public bool Created;
        public uint VolumeSerial;
        public ulong FileIndex;
    }

    public static class SecureLogNative
    {
        const uint GENERIC_WRITE = 0x40000000;
        const uint READ_CONTROL = 0x00020000;
        const uint FILE_SHARE_READ = 0x00000001;
        const uint FILE_SHARE_WRITE = 0x00000002;
        const uint CREATE_NEW = 1;
        const uint OPEN_EXISTING = 3;
        const uint FILE_ATTRIBUTE_NORMAL = 0x00000080;
        const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
        const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
        const int ERROR_FILE_EXISTS = 80;
        const int ERROR_ALREADY_EXISTS = 183;
        const uint FILE_TYPE_DISK = 0x0001;
        const int SE_FILE_OBJECT = 1;
        const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        const uint DACL_SECURITY_INFORMATION = 0x00000004;
        const int FileAttributeTagInfoClass = 9;
        const int FILE_ALL_ACCESS = 0x001F01FF;

        [StructLayout(LayoutKind.Sequential)]
        struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct FILE_ATTRIBUTE_TAG_INFO
        {
            public uint FileAttributes;
            public uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandleEx(SafeFileHandle hFile, int infoClass,
            IntPtr lpFileInformation, uint dwBufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(SafeFileHandle hFile,
            out BY_HANDLE_FILE_INFORMATION lpFileInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetFileType(SafeFileHandle hFile);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint GetSecurityInfo(SafeFileHandle handle, int objectType,
            uint securityInfo, out IntPtr ppsidOwner, out IntPtr ppsidGroup,
            out IntPtr ppDacl, out IntPtr ppSacl, out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern uint GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string sddl, uint revision, out IntPtr pSecurityDescriptor, out uint size);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        static string CurrentSid()
        {
            WindowsIdentity me = WindowsIdentity.GetCurrent();
            if (me == null || me.User == null)
            {
                throw new SecureLogRefusal("no-current-sid");
            }
            return me.User.Value;
        }

        // The whole point of the native create: the security descriptor is built
        // BEFORE the file exists and handed to CreateFileW, so the object is
        // owner-only from the first instant it is nameable. Creating with the
        // inherited/default DACL and calling Set-Acl afterwards leaves a window
        // in which anyone the parent directory trusts can open the log.
        //   O:sid  owner is us
        //   G:sid  group is us
        //   D:P    DACL protected - inheritance blocked
        //   (A;;FA;;;sid)  exactly one ACE: us, file-all-access
        static string CreationSddl(string sid)
        {
            return "O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")";
        }

        public static SecureLogOpen Open(string path)
        {
            string sid = CurrentSid();
            SafeFileHandle handle = null;
            bool created = false;

            IntPtr pSd = IntPtr.Zero;
            IntPtr pAttrs = IntPtr.Zero;
            try
            {
                uint sdSize;
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        CreationSddl(sid), 1, out pSd, out sdSize))
                {
                    throw new SecureLogRefusal("security-descriptor-failed");
                }
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.lpSecurityDescriptor = pSd;
                sa.bInheritHandle = 0;
                pAttrs = Marshal.AllocHGlobal(sa.nLength);
                Marshal.StructureToPtr(sa, pAttrs, false);

                handle = CreateFileW(path, GENERIC_WRITE | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, pAttrs, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    handle = null;
                    if (err != ERROR_FILE_EXISTS && err != ERROR_ALREADY_EXISTS)
                    {
                        throw new SecureLogRefusal("create-failed");
                    }
                }
                else
                {
                    created = true;
                }
            }
            finally
            {
                if (pAttrs != IntPtr.Zero) { Marshal.FreeHGlobal(pAttrs); }
                if (pSd != IntPtr.Zero) { LocalFree(pSd); }
            }

            if (handle == null)
            {
                // Pre-existing. FILE_FLAG_OPEN_REPARSE_POINT opens the reparse
                // point ITSELF rather than its target, so a planted symlink or
                // junction can be rejected on its own attributes instead of
                // silently redirecting the write. Share mode omits DELETE, so
                // while this handle is held the name cannot be renamed away or
                // replaced underneath the verification.
                handle = CreateFileW(path, GENERIC_WRITE | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    handle.Dispose();
                    throw new SecureLogRefusal("open-failed");
                }
            }

            try
            {
                SecureLogOpen result = new SecureLogOpen();
                result.Handle = handle;
                result.Created = created;
                VerifyKind(handle);
                if (!created)
                {
                    // A file this call just created carries the descriptor above
                    // by construction. Anything else has to prove itself.
                    VerifySecurity(handle, sid);
                }
                Identify(handle, result);
                return result;
            }
            catch
            {
                handle.Dispose();
                throw;
            }
        }

        // Every decision below is taken from the OPEN HANDLE. A path lookup can
        // describe a different object than the one being written to; a handle
        // cannot.
        static void VerifyKind(SafeFileHandle handle)
        {
            if (GetFileType(handle) != FILE_TYPE_DISK)
            {
                throw new SecureLogRefusal("not-a-disk-file");
            }
            int size = Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO));
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfoClass, buf, (uint)size))
                {
                    throw new SecureLogRefusal("attribute-query-failed");
                }
                FILE_ATTRIBUTE_TAG_INFO info =
                    (FILE_ATTRIBUTE_TAG_INFO)Marshal.PtrToStructure(buf, typeof(FILE_ATTRIBUTE_TAG_INFO));
                if ((info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    throw new SecureLogRefusal("reparse-point");
                }
                if ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    throw new SecureLogRefusal("directory");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        static void VerifySecurity(SafeFileHandle handle, string sid)
        {
            IntPtr owner, group, dacl, sacl, pSd;
            uint rc = GetSecurityInfo(handle, SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                out owner, out group, out dacl, out sacl, out pSd);
            if (rc != 0 || pSd == IntPtr.Zero)
            {
                throw new SecureLogRefusal("security-query-failed");
            }
            byte[] raw;
            try
            {
                uint len = GetSecurityDescriptorLength(pSd);
                raw = new byte[len];
                Marshal.Copy(pSd, raw, 0, (int)len);
            }
            finally
            {
                LocalFree(pSd);
            }

            RawSecurityDescriptor sd = new RawSecurityDescriptor(raw, 0);
            if (sd.Owner == null || sd.Owner.Value != sid)
            {
                throw new SecureLogRefusal("owner-mismatch");
            }
            if ((sd.ControlFlags & ControlFlags.DiscretionaryAclProtected) == 0)
            {
                throw new SecureLogRefusal("dacl-not-protected");
            }
            RawAcl acl = sd.DiscretionaryAcl;
            if (acl == null)
            {
                throw new SecureLogRefusal("no-dacl");
            }
            int granted = 0;
            bool sawSelf = false;
            for (int i = 0; i < acl.Count; i++)
            {
                CommonAce ace = acl[i] as CommonAce;
                if (ace == null)
                {
                    // Object/callback ACE forms are not interpreted here, and an
                    // ACE we cannot read is not an ACE we can clear.
                    throw new SecureLogRefusal("unsupported-ace");
                }
                bool self = ace.SecurityIdentifier.Value == sid;
                if (ace.AceQualifier == AceQualifier.AccessAllowed)
                {
                    if (!self)
                    {
                        throw new SecureLogRefusal("foreign-allow-ace");
                    }
                    sawSelf = true;
                    granted |= ace.AccessMask;
                }
                else if (ace.AceQualifier == AceQualifier.AccessDenied)
                {
                    if (self)
                    {
                        // Allow ACEs stop describing effective rights once a Deny
                        // on the same principal exists.
                        throw new SecureLogRefusal("self-deny-ace");
                    }
                }
                else
                {
                    throw new SecureLogRefusal("unsupported-ace-qualifier");
                }
            }
            if (!sawSelf)
            {
                throw new SecureLogRefusal("no-self-ace");
            }
            if ((granted & FILE_ALL_ACCESS) != FILE_ALL_ACCESS)
            {
                throw new SecureLogRefusal("insufficient-rights");
            }
        }

        // Volume serial + file index is the object's identity. It is returned so
        // a test can prove the handle that was verified is the handle that was
        // written, without a path-keyed cache ever existing.
        static void Identify(SafeFileHandle handle, SecureLogOpen result)
        {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
            {
                throw new SecureLogRefusal("identity-query-failed");
            }
            result.VolumeSerial = info.dwVolumeSerialNumber;
            result.FileIndex = ((ulong)info.nFileIndexHigh << 32) | info.nFileIndexLow;
        }
    }
}
