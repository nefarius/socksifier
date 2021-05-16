#pragma once


// http://www.exploit-monday.com/2013/06/undocumented-ntquerysysteminformation.html

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0x0000,
    SystemProcessorInformation = 0x0001,
    SystemPerformanceInformation = 0x0002,
    SystemTimeOfDayInformation = 0x0003,
    SystemPathInformation = 0x0004,
    SystemProcessInformation = 0x0005,
    SystemCallCountInformation = 0x0006,
    SystemDeviceInformation = 0x0007,
    SystemProcessorPerformanceInformation = 0x0008,
    SystemFlagsInformation = 0x0009,
    SystemCallTimeInformation = 0x000A,
    SystemModuleInformation = 0x000B,
    SystemLocksInformation = 0x000C,
    SystemStackTraceInformation = 0x000D,
    SystemPagedPoolInformation = 0x000E,
    SystemNonPagedPoolInformation = 0x000F,
    SystemHandleInformation = 0x0010,
    SystemObjectInformation = 0x0011,
    SystemPageFileInformation = 0x0012,
    SystemVdmInstemulInformation = 0x0013,
    SystemVdmBopInformation = 0x0014,
    SystemFileCacheInformation = 0x0015,
    SystemPoolTagInformation = 0x0016,
    SystemInterruptInformation = 0x0017,
    SystemDpcBehaviorInformation = 0x0018,
    SystemFullMemoryInformation = 0x0019,
    SystemLoadGdiDriverInformation = 0x001A,
    SystemUnloadGdiDriverInformation = 0x001B,
    SystemTimeAdjustmentInformation = 0x001C,
    SystemSummaryMemoryInformation = 0x001D,
    SystemMirrorMemoryInformation = 0x001E,
    SystemPerformanceTraceInformation = 0x001F,
    SystemCrashDumpInformation = 0x0020,
    SystemExceptionInformation = 0x0021,
    SystemCrashDumpStateInformation = 0x0022,
    SystemKernelDebuggerInformation = 0x0023,
    SystemContextSwitchInformation = 0x0024,
    SystemRegistryQuotaInformation = 0x0025,
    SystemExtendServiceTableInformation = 0x0026,
    SystemPrioritySeperation = 0x0027,
    SystemVerifierAddDriverInformation = 0x0028,
    SystemVerifierRemoveDriverInformation = 0x0029,
    SystemProcessorIdleInformation = 0x002A,
    SystemLegacyDriverInformation = 0x002B,
    SystemCurrentTimeZoneInformation = 0x002C,
    SystemLookasideInformation = 0x002D,
    SystemTimeSlipNotification = 0x002E,
    SystemSessionCreate = 0x002F,
    SystemSessionDetach = 0x0030,
    SystemSessionInformation = 0x0031,
    SystemRangeStartInformation = 0x0032,
    SystemVerifierInformation = 0x0033,
    SystemVerifierThunkExtend = 0x0034,
    SystemSessionProcessInformation = 0x0035,
    SystemLoadGdiDriverInSystemSpace = 0x0036,
    SystemNumaProcessorMap = 0x0037,
    SystemPrefetcherInformation = 0x0038,
    SystemExtendedProcessInformation = 0x0039,
    SystemRecommendedSharedDataAlignment = 0x003A,
    SystemComPlusPackage = 0x003B,
    SystemNumaAvailableMemory = 0x003C,
    SystemProcessorPowerInformation = 0x003D,
    SystemEmulationBasicInformation = 0x003E,
    SystemEmulationProcessorInformation = 0x003F,
    SystemExtendedHandleInformation = 0x0040,
    SystemLostDelayedWriteInformation = 0x0041,
    SystemBigPoolInformation = 0x0042,
    SystemSessionPoolTagInformation = 0x0043,
    SystemSessionMappedViewInformation = 0x0044,
    SystemHotpatchInformation = 0x0045,
    SystemObjectSecurityMode = 0x0046,
    SystemWatchdogTimerHandler = 0x0047,
    SystemWatchdogTimerInformation = 0x0048,
    SystemLogicalProcessorInformation = 0x0049,
    SystemWow64SharedInformationObsolete = 0x004A,
    SystemRegisterFirmwareTableInformationHandler = 0x004B,
    SystemFirmwareTableInformation = 0x004C,
    SystemModuleInformationEx = 0x004D,
    SystemVerifierTriageInformation = 0x004E,
    SystemSuperfetchInformation = 0x004F,
    SystemMemoryListInformation = 0x0050,
    SystemFileCacheInformationEx = 0x0051,
    SystemThreadPriorityClientIdInformation = 0x0052,
    SystemProcessorIdleCycleTimeInformation = 0x0053,
    SystemVerifierCancellationInformation = 0x0054,
    SystemProcessorPowerInformationEx = 0x0055,
    SystemRefTraceInformation = 0x0056,
    SystemSpecialPoolInformation = 0x0057,
    SystemProcessIdInformation = 0x0058,
    SystemErrorPortInformation = 0x0059,
    SystemBootEnvironmentInformation = 0x005A,
    SystemHypervisorInformation = 0x005B,
    SystemVerifierInformationEx = 0x005C,
    SystemTimeZoneInformation = 0x005D,
    SystemImageFileExecutionOptionsInformation = 0x005E,
    SystemCoverageInformation = 0x005F,
    SystemPrefetchPatchInformation = 0x0060,
    SystemVerifierFaultsInformation = 0x0061,
    SystemSystemPartitionInformation = 0x0062,
    SystemSystemDiskInformation = 0x0063,
    SystemProcessorPerformanceDistribution = 0x0064,
    SystemNumaProximityNodeInformation = 0x0065,
    SystemDynamicTimeZoneInformation = 0x0066,
    SystemCodeIntegrityInformation = 0x0067,
    SystemProcessorMicrocodeUpdateInformation = 0x0068,
    SystemProcessorBrandString = 0x0069,
    SystemVirtualAddressInformation = 0x006A,
    SystemLogicalProcessorAndGroupInformation = 0x006B,
    SystemProcessorCycleTimeInformation = 0x006C,
    SystemStoreInformation = 0x006D,
    SystemRegistryAppendString = 0x006E,
    SystemAitSamplingValue = 0x006F,
    SystemVhdBootInformation = 0x0070,
    SystemCpuQuotaInformation = 0x0071,
    SystemNativeBasicInformation = 0x0072,
    SystemErrorPortTimeouts = 0x0073,
    SystemLowPriorityIoInformation = 0x0074,
    SystemBootEntropyInformation = 0x0075,
    SystemVerifierCountersInformation = 0x0076,
    SystemPagedPoolInformationEx = 0x0077,
    SystemSystemPtesInformationEx = 0x0078,
    SystemNodeDistanceInformation = 0x0079,
    SystemAcpiAuditInformation = 0x007A,
    SystemBasicPerformanceInformation = 0x007B,
    SystemQueryPerformanceCounterInformation = 0x007C,
    SystemSessionBigPoolInformation = 0x007D,
    SystemBootGraphicsInformation = 0x007E,
    SystemScrubPhysicalMemoryInformation = 0x007F,
    SystemBadPageInformation = 0x0080,
    SystemProcessorProfileControlArea = 0x0081,
    SystemCombinePhysicalMemoryInformation = 0x0082,
    SystemEntropyInterruptTimingInformation = 0x0083,
    SystemConsoleInformation = 0x0084,
    SystemPlatformBinaryInformation = 0x0085,
    SystemThrottleNotificationInformation = 0x0086,
    SystemHypervisorProcessorCountInformation = 0x0087,
    SystemDeviceDataInformation = 0x0088,
    SystemDeviceDataEnumerationInformation = 0x0089,
    SystemMemoryTopologyInformation = 0x008A,
    SystemMemoryChannelInformation = 0x008B,
    SystemBootLogoInformation = 0x008C,
    SystemProcessorPerformanceInformationEx = 0x008D,
    SystemSpare0 = 0x008E,
    SystemSecureBootPolicyInformation = 0x008F,
    SystemPageFileInformationEx = 0x0090,
    SystemSecureBootInformation = 0x0091,
    SystemEntropyInterruptTimingRawInformation = 0x0092,
    SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
    SystemFullProcessInformation = 0x0094,
    MaxSystemInfoClass = 0x0095
};

// //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct _UNICODE_STRING {                                          // Size =  8
    USHORT Length;                                                        // Size =  2 | Offset =  0
    USHORT MaximumLength;                                                 // Size =  2 | Offset =  2
    PWSTR  Buffer;                                                        // Size =  4 | Offset =  4
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;


struct _SYSTEM_BASIC_INFORMATION                                          // Size = 44
{
    ULONG Reserved;                                                       // Size =  4 | Offset =   0
    ULONG TimerResolution;                                                // Size =  4 | Offset =   4
    ULONG PageSize;                                                       // Size =  4 | Offset =   8
    ULONG NumberOfPhysicalPages;                                          // Size =  4 | Offset =  12
    ULONG LowestPhysicalPageNumber;                                       // Size =  4 | Offset =  16
    ULONG HighestPhysicalPageNumber;                                      // Size =  4 | Offset =  20
    ULONG AllocationGranularity;                                          // Size =  4 | Offset =  24
    ULONG MinimumUserModeAddress;                                         // Size =  4 | Offset =  28
    ULONG MaximumUserModeAddress;                                         // Size =  4 | Offset =  32
    ULONG ActiveProcessorsAffinityMask;                                   // Size =  4 | Offset =  36
    UCHAR NumberOfProcessors;                                             // Size =  1 | Offset =  40
};

struct _SYSTEM_PROCESSOR_INFORMATION // Size=12
{
    USHORT ProcessorArchitecture; // Size=2 Offset=0
    USHORT ProcessorLevel; // Size=2 Offset=2
    USHORT ProcessorRevision; // Size=2 Offset=4
    USHORT MaximumProcessors; // Size=2 Offset=6
    ULONG ProcessorFeatureBits; // Size=4 Offset=8
};

struct _SYSTEM_PERFORMANCE_INFORMATION // Size=344
{
    LARGE_INTEGER IdleProcessTime; // Size=8 Offset=0
    LARGE_INTEGER IoReadTransferCount; // Size=8 Offset=8
    LARGE_INTEGER IoWriteTransferCount; // Size=8 Offset=16
    LARGE_INTEGER IoOtherTransferCount; // Size=8 Offset=24
    ULONG IoReadOperationCount; // Size=4 Offset=32
    ULONG IoWriteOperationCount; // Size=4 Offset=36
    ULONG IoOtherOperationCount; // Size=4 Offset=40
    ULONG AvailablePages; // Size=4 Offset=44
    ULONG CommittedPages; // Size=4 Offset=48
    ULONG CommitLimit; // Size=4 Offset=52
    ULONG PeakCommitment; // Size=4 Offset=56
    ULONG PageFaultCount; // Size=4 Offset=60
    ULONG CopyOnWriteCount; // Size=4 Offset=64
    ULONG TransitionCount; // Size=4 Offset=68
    ULONG CacheTransitionCount; // Size=4 Offset=72
    ULONG DemandZeroCount; // Size=4 Offset=76
    ULONG PageReadCount; // Size=4 Offset=80
    ULONG PageReadIoCount; // Size=4 Offset=84
    ULONG CacheReadCount; // Size=4 Offset=88
    ULONG CacheIoCount; // Size=4 Offset=92
    ULONG DirtyPagesWriteCount; // Size=4 Offset=96
    ULONG DirtyWriteIoCount; // Size=4 Offset=100
    ULONG MappedPagesWriteCount; // Size=4 Offset=104
    ULONG MappedWriteIoCount; // Size=4 Offset=108
    ULONG PagedPoolPages; // Size=4 Offset=112
    ULONG NonPagedPoolPages; // Size=4 Offset=116
    ULONG PagedPoolAllocs; // Size=4 Offset=120
    ULONG PagedPoolFrees; // Size=4 Offset=124
    ULONG NonPagedPoolAllocs; // Size=4 Offset=128
    ULONG NonPagedPoolFrees; // Size=4 Offset=132
    ULONG FreeSystemPtes; // Size=4 Offset=136
    ULONG ResidentSystemCodePage; // Size=4 Offset=140
    ULONG TotalSystemDriverPages; // Size=4 Offset=144
    ULONG TotalSystemCodePages; // Size=4 Offset=148
    ULONG NonPagedPoolLookasideHits; // Size=4 Offset=152
    ULONG PagedPoolLookasideHits; // Size=4 Offset=156
    ULONG AvailablePagedPoolPages; // Size=4 Offset=160
    ULONG ResidentSystemCachePage; // Size=4 Offset=164
    ULONG ResidentPagedPoolPage; // Size=4 Offset=168
    ULONG ResidentSystemDriverPage; // Size=4 Offset=172
    ULONG CcFastReadNoWait; // Size=4 Offset=176
    ULONG CcFastReadWait; // Size=4 Offset=180
    ULONG CcFastReadResourceMiss; // Size=4 Offset=184
    ULONG CcFastReadNotPossible; // Size=4 Offset=188
    ULONG CcFastMdlReadNoWait; // Size=4 Offset=192
    ULONG CcFastMdlReadWait; // Size=4 Offset=196
    ULONG CcFastMdlReadResourceMiss; // Size=4 Offset=200
    ULONG CcFastMdlReadNotPossible; // Size=4 Offset=204
    ULONG CcMapDataNoWait; // Size=4 Offset=208
    ULONG CcMapDataWait; // Size=4 Offset=212
    ULONG CcMapDataNoWaitMiss; // Size=4 Offset=216
    ULONG CcMapDataWaitMiss; // Size=4 Offset=220
    ULONG CcPinMappedDataCount; // Size=4 Offset=224
    ULONG CcPinReadNoWait; // Size=4 Offset=228
    ULONG CcPinReadWait; // Size=4 Offset=232
    ULONG CcPinReadNoWaitMiss; // Size=4 Offset=236
    ULONG CcPinReadWaitMiss; // Size=4 Offset=240
    ULONG CcCopyReadNoWait; // Size=4 Offset=244
    ULONG CcCopyReadWait; // Size=4 Offset=248
    ULONG CcCopyReadNoWaitMiss; // Size=4 Offset=252
    ULONG CcCopyReadWaitMiss; // Size=4 Offset=256
    ULONG CcMdlReadNoWait; // Size=4 Offset=260
    ULONG CcMdlReadWait; // Size=4 Offset=264
    ULONG CcMdlReadNoWaitMiss; // Size=4 Offset=268
    ULONG CcMdlReadWaitMiss; // Size=4 Offset=272
    ULONG CcReadAheadIos; // Size=4 Offset=276
    ULONG CcLazyWriteIos; // Size=4 Offset=280
    ULONG CcLazyWritePages; // Size=4 Offset=284
    ULONG CcDataFlushes; // Size=4 Offset=288
    ULONG CcDataPages; // Size=4 Offset=292
    ULONG ContextSwitches; // Size=4 Offset=296
    ULONG FirstLevelTbFills; // Size=4 Offset=300
    ULONG SecondLevelTbFills; // Size=4 Offset=304
    ULONG SystemCalls; // Size=4 Offset=308
    ULONGLONG CcTotalDirtyPages; // Size=8 Offset=312
    ULONGLONG CcDirtyPageThreshold; // Size=8 Offset=320
    LONGLONG ResidentAvailablePages; // Size=8 Offset=328
    ULONGLONG SharedCommittedPages; // Size=8 Offset=336
};

struct _SYSTEM_TIMEOFDAY_INFORMATION // Size=48
{
    LARGE_INTEGER BootTime; // Size=8 Offset=0
    LARGE_INTEGER CurrentTime; // Size=8 Offset=8
    LARGE_INTEGER TimeZoneBias; // Size=8 Offset=16
    ULONG TimeZoneId; // Size=4 Offset=24
    ULONG Reserved; // Size=4 Offset=28
    ULONGLONG BootTimeBias; // Size=8 Offset=32
    ULONGLONG SleepTimeBias; // Size=8 Offset=40
};

typedef struct _SYSTEM_PROCESS_INFORMATION // Size=184
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG NumberOfThreads; // Size=4 Offset=4
    LARGE_INTEGER WorkingSetPrivateSize; // Size=8 Offset=8
    ULONG HardFaultCount; // Size=4 Offset=16
    ULONG NumberOfThreadsHighWatermark; // Size=4 Offset=20
    ULONGLONG CycleTime; // Size=8 Offset=24
    LARGE_INTEGER CreateTime; // Size=8 Offset=32
    LARGE_INTEGER UserTime; // Size=8 Offset=40
    LARGE_INTEGER KernelTime; // Size=8 Offset=48
    UNICODE_STRING ImageName; // Size=8 Offset=56
    LONG BasePriority; // Size=4 Offset=64
    PVOID UniqueProcessId; // Size=4 Offset=68
    PVOID InheritedFromUniqueProcessId; // Size=4 Offset=72
    ULONG HandleCount; // Size=4 Offset=76
    ULONG SessionId; // Size=4 Offset=80
    ULONG UniqueProcessKey; // Size=4 Offset=84
    ULONG PeakVirtualSize; // Size=4 Offset=88
    ULONG VirtualSize; // Size=4 Offset=92
    ULONG PageFaultCount; // Size=4 Offset=96
    ULONG PeakWorkingSetSize; // Size=4 Offset=100
    ULONG WorkingSetSize; // Size=4 Offset=104
    ULONG QuotaPeakPagedPoolUsage; // Size=4 Offset=108
    ULONG QuotaPagedPoolUsage; // Size=4 Offset=112
    ULONG QuotaPeakNonPagedPoolUsage; // Size=4 Offset=116
    ULONG QuotaNonPagedPoolUsage; // Size=4 Offset=120
    ULONG PagefileUsage; // Size=4 Offset=124
    ULONG PeakPagefileUsage; // Size=4 Offset=128
    ULONG PrivatePageCount; // Size=4 Offset=132
    LARGE_INTEGER ReadOperationCount; // Size=8 Offset=136
    LARGE_INTEGER WriteOperationCount; // Size=8 Offset=144
    LARGE_INTEGER OtherOperationCount; // Size=8 Offset=152
    LARGE_INTEGER ReadTransferCount; // Size=8 Offset=160
    LARGE_INTEGER WriteTransferCount; // Size=8 Offset=168
    LARGE_INTEGER OtherTransferCount; // Size=8 Offset=176
} SYSTEM_PROCESS_INFORMATION;

struct _SYSTEM_CALL_COUNT_INFORMATION // Size=8
{
    ULONG Length; // Size=4 Offset=0
    ULONG NumberOfTables; // Size=4 Offset=4
};

struct _SYSTEM_DEVICE_INFORMATION // Size=24
{
    ULONG NumberOfDisks; // Size=4 Offset=0
    ULONG NumberOfFloppies; // Size=4 Offset=4
    ULONG NumberOfCdRoms; // Size=4 Offset=8
    ULONG NumberOfTapes; // Size=4 Offset=12
    ULONG NumberOfSerialPorts; // Size=4 Offset=16
    ULONG NumberOfParallelPorts; // Size=4 Offset=20
};

struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION // Size=48
{
    LARGE_INTEGER IdleTime; // Size=8 Offset=0
    LARGE_INTEGER KernelTime; // Size=8 Offset=8
    LARGE_INTEGER UserTime; // Size=8 Offset=16
    LARGE_INTEGER DpcTime; // Size=8 Offset=24
    LARGE_INTEGER InterruptTime; // Size=8 Offset=32
    ULONG InterruptCount; // Size=4 Offset=40
};

typedef enum _SYSTEM_GLOBAL_FLAGS
{
    FLG_DISABLE_DBGPRINT = 0x08000000,
    FLG_KERNEL_STACK_TRACE_DB = 0x00002000,
    FLG_USER_STACK_TRACE_DB = 0x00001000,
    FLG_DEBUG_INITIAL_COMMAND = 0x00000004,
    FLG_DEBUG_INITIAL_COMMAND_EX = 0x04000000,
    FLG_HEAP_DISABLE_COALESCING = 0x00200000,
    FLG_DISABLE_PAGE_KERNEL_STACKS = 0x00080000,
    FLG_DISABLE_PROTDLLS = 0x80000000,
    FLG_DISABLE_STACK_EXTENSION = 0x00010000,
    FLG_CRITSEC_EVENT_CREATION = 0x10000000,
    FLG_APPLICATION_VERIFIER = 0x00000100,
    FLG_ENABLE_HANDLE_EXCEPTIONS = 0x40000000,
    FLG_ENABLE_CLOSE_EXCEPTIONS = 0x00400000,
    FLG_ENABLE_CSRDEBUG = 0x00020000,
    FLG_ENABLE_EXCEPTION_LOGGING = 0x00800000,
    FLG_HEAP_ENABLE_FREE_CHECK = 0x00000020,
    FLG_HEAP_VALIDATE_PARAMETERS = 0x00000040,
    FLG_HEAP_ENABLE_TAGGING = 0x00000800,
    FLG_HEAP_ENABLE_TAG_BY_DLL = 0x00008000,
    FLG_HEAP_ENABLE_TAIL_CHECK = 0x00000010,
    FLG_HEAP_VALIDATE_ALL = 0x00000080,
    FLG_ENABLE_KDEBUG_SYMBOL_LOAD = 0x00040000,
    FLG_ENABLE_HANDLE_TYPE_TAGGING = 0x01000000,
    FLG_HEAP_PAGE_ALLOCS = 0x02000000,
    FLG_POOL_ENABLE_TAGGING = 0x00000400,
    FLG_ENABLE_SYSTEM_CRIT_BREAKS = 0x00100000,
    FLG_MAINTAIN_OBJECT_TYPELIST = 0x00004000,
    FLG_MONITOR_SILENT_PROCESS_EXIT = 0x00000200,
    FLG_SHOW_LDR_SNAPS = 0x00000002,
    FLG_STOP_ON_EXCEPTION = 0x00000001,
    FLG_STOP_ON_HUNG_GUI = 0x00000008
} SYSTEM_GLOBAL_FLAGS;

struct _SYSTEM_FLAGS_INFORMATION // Size=4
{
    SYSTEM_GLOBAL_FLAGS Flags; // Size=4 Offset=0
};

struct _SYSTEM_CALL_TIME_INFORMATION // Size=16
{
    ULONG Length; // Size=4 Offset=0
    ULONG TotalCalls; // Size=4 Offset=4
    LARGE_INTEGER TimeOfCalls[1]; // Size=8 Offset=8
};

typedef struct _SYSTEM_MODULE // Size=280
{
    USHORT Reserved1; // Size=2 Offset=0
    USHORT Reserved2; // Size=2 Offset=2
    ULONG ImageBaseAddress; // Size=4 Offset=4
    ULONG ImageSize; // Size=4 Offset=8
    ULONG Flags; // Size=4 Offset=12
    USHORT Index; // Size=2 Offset=16
    USHORT Rank; // Size=2 Offset=18
    USHORT LoadCount; // Size=2 Offset=20
    USHORT NameOffset; // Size=2 Offset=22
    UCHAR Name[256]; // Size=256 Offset=24
} SYSTEM_MODULE;

struct _SYSTEM_MODULE_INFORMATION // Size=284
{
    ULONG Count; // Size=4 Offset=0
    SYSTEM_MODULE Modules[1]; // Size=280 Offset=4
};

typedef struct _SYSTEM_LOCK // Size=36
{
    PVOID Address; // Size=4 Offset=0
    USHORT Type; // Size=2 Offset=4
    USHORT Reserved1; // Size=2 Offset=6
    ULONG ExclusiveOwnerThreadId; // Size=4 Offset=8
    ULONG ActiveCount; // Size=4 Offset=12
    ULONG ContentionCount; // Size=4 Offset=16
    ULONG Reserved2[2]; // Size=8 Offset=20
    ULONG NumberOfSharedWaiters; // Size=4 Offset=28
    ULONG NumberOfExclusiveWaiters; // Size=4 Offset=32
} SYSTEM_LOCK;

struct _SYSTEM_LOCK_INFORMATION // Size=40
{
    ULONG Count; // Size=4 Offset=0
    SYSTEM_LOCK Locks[1]; // Size=36 Offset=4
};

typedef enum _SYSTEM_HANDLE_FLAGS
{
    PROTECT_FROM_CLOSE = 1,
    INHERIT = 2
} SYSTEM_HANDLE_FLAGS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO // Size=16
{
    USHORT UniqueProcessId; // Size=2 Offset=0
    USHORT CreatorBackTraceIndex; // Size=2 Offset=2
    UCHAR ObjectTypeIndex; // Size=1 Offset=4
    BYTE HandleAttributes; // Size=1 Offset=5
    USHORT HandleValue; // Size=2 Offset=6
    PVOID Object; // Size=4 Offset=8
    ULONG GrantedAccess; // Size=4 Offset=12
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION // Size=20
{
    ULONG NumberOfHandles; // Size=4 Offset=0
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1]; // Size=16 Offset=4
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

struct _SYSTEM_OBJECTTYPE_INFORMATION // Size=56
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG NumberOfObjects; // Size=4 Offset=4
    ULONG NumberOfHandles; // Size=4 Offset=8
    ULONG TypeIndex; // Size=4 Offset=12
    ULONG InvalidAttributes; // Size=4 Offset=16
    GENERIC_MAPPING GenericMapping; // Size=16 Offset=20
    ULONG ValidAccessMask; // Size=4 Offset=36
    ULONG PoolType; // Size=4 Offset=40
    UCHAR SecurityRequired; // Size=1 Offset=44
    UCHAR WaitableObject; // Size=1 Offset=45
    UNICODE_STRING TypeName; // Size=8 Offset=48
};

typedef struct _OBJECT_NAME_INFORMATION // Size=8
{
    UNICODE_STRING Name; // Size=8 Offset=0
} OBJECT_NAME_INFORMATION;

struct _SYSTEM_OBJECT_INFORMATION // Size=48
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    PVOID Object; // Size=4 Offset=4
    PVOID CreatorUniqueProcess; // Size=4 Offset=8
    USHORT CreatorBackTraceIndex; // Size=2 Offset=12
    USHORT Flags; // Size=2 Offset=14
    LONG PointerCount; // Size=4 Offset=16
    LONG HandleCount; // Size=4 Offset=20
    ULONG PagedPoolCharge; // Size=4 Offset=24
    ULONG NonPagedPoolCharge; // Size=4 Offset=28
    PVOID ExclusiveProcessId; // Size=4 Offset=32
    PVOID SecurityDescriptor; // Size=4 Offset=36
    OBJECT_NAME_INFORMATION NameInfo; // Size=8 Offset=40
};

struct _SYSTEM_PAGEFILE_INFORMATION // Size=24
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG TotalSize; // Size=4 Offset=4
    ULONG TotalInUse; // Size=4 Offset=8
    ULONG PeakUsage; // Size=4 Offset=12
    UNICODE_STRING PageFileName; // Size=8 Offset=16
};

struct _SYSTEM_VDM_INSTEMUL_INFO // Size=136
{
    ULONG SegmentNotPresent; // Size=4 Offset=0
    ULONG VdmOpcode0F; // Size=4 Offset=4
    ULONG OpcodeESPrefix; // Size=4 Offset=8
    ULONG OpcodeCSPrefix; // Size=4 Offset=12
    ULONG OpcodeSSPrefix; // Size=4 Offset=16
    ULONG OpcodeDSPrefix; // Size=4 Offset=20
    ULONG OpcodeFSPrefix; // Size=4 Offset=24
    ULONG OpcodeGSPrefix; // Size=4 Offset=28
    ULONG OpcodeOPER32Prefix; // Size=4 Offset=32
    ULONG OpcodeADDR32Prefix; // Size=4 Offset=36
    ULONG OpcodeINSB; // Size=4 Offset=40
    ULONG OpcodeINSW; // Size=4 Offset=44
    ULONG OpcodeOUTSB; // Size=4 Offset=48
    ULONG OpcodeOUTSW; // Size=4 Offset=52
    ULONG OpcodePUSHF; // Size=4 Offset=56
    ULONG OpcodePOPF; // Size=4 Offset=60
    ULONG OpcodeINTnn; // Size=4 Offset=64
    ULONG OpcodeINTO; // Size=4 Offset=68
    ULONG OpcodeIRET; // Size=4 Offset=72
    ULONG OpcodeINBimm; // Size=4 Offset=76
    ULONG OpcodeINWimm; // Size=4 Offset=80
    ULONG OpcodeOUTBimm; // Size=4 Offset=84
    ULONG OpcodeOUTWimm; // Size=4 Offset=88
    ULONG OpcodeINB; // Size=4 Offset=92
    ULONG OpcodeINW; // Size=4 Offset=96
    ULONG OpcodeOUTB; // Size=4 Offset=100
    ULONG OpcodeOUTW; // Size=4 Offset=104
    ULONG OpcodeLOCKPrefix; // Size=4 Offset=108
    ULONG OpcodeREPNEPrefix; // Size=4 Offset=112
    ULONG OpcodeREPPrefix; // Size=4 Offset=116
    ULONG OpcodeHLT; // Size=4 Offset=120
    ULONG OpcodeCLI; // Size=4 Offset=124
    ULONG OpcodeSTI; // Size=4 Offset=128
    ULONG BopCount; // Size=4 Offset=132
};

struct _SYSTEM_FILECACHE_INFORMATION // Size=36
{
    ULONG CurrentSize; // Size=4 Offset=0
    ULONG PeakSize; // Size=4 Offset=4
    ULONG PageFaultCount; // Size=4 Offset=8
    ULONG MinimumWorkingSet; // Size=4 Offset=12
    ULONG MaximumWorkingSet; // Size=4 Offset=16
    ULONG CurrentSizeIncludingTransitionInPages; // Size=4 Offset=20
    ULONG PeakSizeIncludingTransitionInPages; // Size=4 Offset=24
    ULONG TransitionRePurposeCount; // Size=4 Offset=28
    ULONG Flags; // Size=4 Offset=32
};

typedef struct _SYSTEM_POOLTAG // Size=28
{
    UCHAR Tag[4]; // Size=4 Offset=0
    ULONG PagedAllocs; // Size=4 Offset=4
    ULONG PagedFrees; // Size=4 Offset=8
    ULONG PagedUsed; // Size=4 Offset=12
    ULONG NonPagedAllocs; // Size=4 Offset=16
    ULONG NonPagedFrees; // Size=4 Offset=20
    ULONG NonPagedUsed; // Size=4 Offset=24
} SYSTEM_POOLTAG;

struct _SYSTEM_POOLTAG_INFORMATION // Size=32
{
    ULONG Count; // Size=4 Offset=0
    SYSTEM_POOLTAG TagInfo[1]; // Size=28 Offset=4
};

struct _SYSTEM_INTERRUPT_INFORMATION // Size=24
{
    ULONG ContextSwitches; // Size=4 Offset=0
    ULONG DpcCount; // Size=4 Offset=4
    ULONG DpcRate; // Size=4 Offset=8
    ULONG TimeIncrement; // Size=4 Offset=12
    ULONG DpcBypassCount; // Size=4 Offset=16
    ULONG ApcBypassCount; // Size=4 Offset=20
};

struct _SYSTEM_DPC_BEHAVIOR_INFORMATION // Size=20
{
    ULONG Spare; // Size=4 Offset=0
    ULONG DpcQueueDepth; // Size=4 Offset=4
    ULONG MinimumDpcRate; // Size=4 Offset=8
    ULONG AdjustDpcThreshold; // Size=4 Offset=12
    ULONG IdealDpcRate; // Size=4 Offset=16
};

struct _SYSTEM_LOADED_GDI_DRIVER_INFORMATION // Size=28
{
    UNICODE_STRING DriverName; // Size=8 Offset=0
    PVOID ImageAddress; // Size=4 Offset=8
    PVOID SectionPointer; // Size=4 Offset=12
    PVOID EntryPoint; // Size=4 Offset=16
    PIMAGE_EXPORT_DIRECTORY ExportSectionPointer; // Size=4 Offset=20
    ULONG ImageLength; // Size=4 Offset=24
};

struct _SYSTEM_UNLOADED_GDI_DRIVER_INFORMATION // Size=28
{
    PVOID ImageAddress; // Size=4 Offset=0
};

struct _SYSTEM_CRASH_DUMP_INFORMATION
{
    HANDLE CrashDumpSectionHandle; // Size=4 Offset=0
};

struct _SYSTEM_EXCEPTION_INFORMATION // Size=16
{
    ULONG AlignmentFixupCount; // Size=4 Offset=0
    ULONG ExceptionDispatchCount; // Size=4 Offset=4
    ULONG FloatingEmulationCount; // Size=4 Offset=8
    ULONG ByteWordEmulationCount; // Size=4 Offset=12
};

typedef enum _SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS
{
    SystemCrashDumpDisable = 0,
    SystemCrashDumpReconfigure = 1,
    SystemCrashDumpInitializationComplete = 2
} SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS;

struct _SYSTEM_CRASH_DUMP_STATE_INFORMATION // Size=4
{
    SYSTEM_CRASH_DUMP_CONFIGURATION_CLASS CrashDumpConfigurationClass; // Size=4 Offset=0
};

struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION // Size=2
{
    UCHAR KernelDebuggerEnabled; // Size=1 Offset=0
    UCHAR KernelDebuggerNotPresent; // Size=1 Offset=1
};

struct _SYSTEM_PRIORITY_SEPARATION
{
    ULONG PrioritySeparation; // Size=4 Offset=0
};


struct _SYSTEM_TIME_ZONE_INFORMATION
{
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

struct _SYSTEM_CONTEXT_SWITCH_INFORMATION // Size=48
{
    ULONG ContextSwitches; // Size=4 Offset=0
    ULONG FindAny; // Size=4 Offset=4
    ULONG FindLast; // Size=4 Offset=8
    ULONG FindIdeal; // Size=4 Offset=12
    ULONG IdleAny; // Size=4 Offset=16
    ULONG IdleCurrent; // Size=4 Offset=20
    ULONG IdleLast; // Size=4 Offset=24
    ULONG IdleIdeal; // Size=4 Offset=28
    ULONG PreemptAny; // Size=4 Offset=32
    ULONG PreemptCurrent; // Size=4 Offset=36
    ULONG PreemptLast; // Size=4 Offset=40
    ULONG SwitchToIdle; // Size=4 Offset=44
};

struct _SYSTEM_REGISTRY_QUOTA_INFORMATION // Size=12
{
    ULONG RegistryQuotaAllowed; // Size=4 Offset=0
    ULONG RegistryQuotaUsed; // Size=4 Offset=4
    ULONG PagedPoolSize; // Size=4 Offset=8
};

struct _SYSTEM_PROCESSOR_IDLE_INFORMATION // Size=48
{
    ULONGLONG IdleTime; // Size=8 Offset=0
    ULONGLONG C1Time; // Size=8 Offset=8
    ULONGLONG C2Time; // Size=8 Offset=16
    ULONGLONG C3Time; // Size=8 Offset=24
    ULONG C1Transitions; // Size=4 Offset=32
    ULONG C2Transitions; // Size=4 Offset=36
    ULONG C3Transitions; // Size=4 Offset=40
    ULONG Padding; // Size=4 Offset=44
};

struct _SYSTEM_LEGACY_DRIVER_INFORMATION // Size=12
{
    ULONG VetoType; // Size=4 Offset=0
    UNICODE_STRING VetoList; // Size=8 Offset=4
};

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32
} POOL_TYPE;

struct _SYSTEM_LOOKASIDE_INFORMATION // Size=32
{
    USHORT CurrentDepth; // Size=2 Offset=0
    USHORT MaximumDepth; // Size=2 Offset=2
    ULONG TotalAllocates; // Size=4 Offset=4
    ULONG AllocateMisses; // Size=4 Offset=8
    ULONG TotalFrees; // Size=4 Offset=12
    ULONG FreeMisses; // Size=4 Offset=16
    POOL_TYPE Type; // Size=4 Offset=20
    ULONG Tag; // Size=4 Offset=24
    ULONG Size; // Size=4 Offset=28
};

struct _SYSTEM_SET_TIME_SLIP_EVENT
{
    HANDLE TimeSlipEvent;
};

struct _SYSTEM_SESSION
{
    ULONG SessionId;
};

struct _SYSTEM_RANGE_START_INFORMATION
{
    PVOID SystemRangeStart;
};

typedef struct _SYSTEM_VERIFIER_INFORMATION // Size=104
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG Level; // Size=4 Offset=4
    UNICODE_STRING DriverName; // Size=8 Offset=8
    ULONG RaiseIrqls; // Size=4 Offset=16
    ULONG AcquireSpinLocks; // Size=4 Offset=20
    ULONG SynchronizeExecutions; // Size=4 Offset=24
    ULONG AllocationsAttempted; // Size=4 Offset=28
    ULONG AllocationsSucceeded; // Size=4 Offset=32
    ULONG AllocationsSucceededSpecialPool; // Size=4 Offset=36
    ULONG AllocationsWithNoTag; // Size=4 Offset=40
    ULONG TrimRequests; // Size=4 Offset=44
    ULONG Trims; // Size=4 Offset=48
    ULONG AllocationsFailed; // Size=4 Offset=52
    ULONG AllocationsFailedDeliberately; // Size=4 Offset=56
    ULONG Loads; // Size=4 Offset=60
    ULONG Unloads; // Size=4 Offset=64
    ULONG UnTrackedPool; // Size=4 Offset=68
    ULONG CurrentPagedPoolAllocations; // Size=4 Offset=72
    ULONG CurrentNonPagedPoolAllocations; // Size=4 Offset=76
    ULONG PeakPagedPoolAllocations; // Size=4 Offset=80
    ULONG PeakNonPagedPoolAllocations; // Size=4 Offset=84
    ULONG PagedPoolUsageInBytes; // Size=4 Offset=88
    ULONG NonPagedPoolUsageInBytes; // Size=4 Offset=92
    ULONG PeakPagedPoolUsageInBytes; // Size=4 Offset=96
    ULONG PeakNonPagedPoolUsageInBytes; // Size=4 Offset=100
} SYSTEM_VERIFIER_INFORMATION;

struct _SYSTEM_SESSION_PROCESS_INFORMATION // Size=12
{
    ULONG SessionId; // Size=4 Offset=0
    ULONG SizeOfBuf; // Size=4 Offset=4
    PVOID Buffer; // Size=4 Offset=8
};

typedef struct _SYSTEM_POOL_BLOCK
{
    BOOLEAN Allocated;
    USHORT Unknown;
    ULONG Size;
    CHAR Tag[4];
} SYSTEM_POOL_BLOCK;

struct _SYSTEM_POOL_BLOCKS_INFORMATION
{
    ULONG PoolSize;
    PVOID PoolBase;
    USHORT PoolAlignment;
    ULONG NumberOfBlocks;
    SYSTEM_POOL_BLOCK PoolBlocks[1];
};

typedef struct _SYSTEM_MEMORY_USAGE
{
    PVOID Name;
    USHORT Valid;
    USHORT Standby;
    USHORT Modified;
    USHORT PageTables;
} SYSTEM_MEMORY_USAGE;

struct _SYSTEM_MEMORY_USAGE_INFORMATION
{
    ULONG Reserved;
    PVOID EndOfData;
    SYSTEM_MEMORY_USAGE MemoryUsage[1];
};

typedef struct _CLIENT_ID // Size=8
{
    PVOID UniqueProcess; // Size=4 Offset=0
    PVOID UniqueThread; // Size=4 Offset=4
} CLIENT_ID;

typedef struct _SYSTEM_THREAD_INFORMATION // Size=64
{
    LARGE_INTEGER KernelTime; // Size=8 Offset=0
    LARGE_INTEGER UserTime; // Size=8 Offset=8
    LARGE_INTEGER CreateTime; // Size=8 Offset=16
    ULONG WaitTime; // Size=4 Offset=24
    PVOID StartAddress; // Size=4 Offset=28
    CLIENT_ID ClientId; // Size=8 Offset=32
    LONG Priority; // Size=4 Offset=40
    LONG BasePriority; // Size=4 Offset=44
    ULONG ContextSwitches; // Size=4 Offset=48
    ULONG ThreadState; // Size=4 Offset=52
    ULONG WaitReason; // Size=4 Offset=56
} SYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION // Size=96
{
    SYSTEM_THREAD_INFORMATION ThreadInfo; // Size=64 Offset=0
    PVOID StackBase; // Size=4 Offset=64
    PVOID StackLimit; // Size=4 Offset=68
    PVOID Win32StartAddress; // Size=4 Offset=72
    PVOID TebBase; // Size=4 Offset=76
    ULONG Reserved2; // Size=4 Offset=80
    ULONG Reserved3; // Size=4 Offset=84
    ULONG Reserved4; // Size=4 Offset=88
} SYSTEM_EXTENDED_THREAD_INFORMATION;

// I have not validated this structure
struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
    SYSTEM_PROCESS_INFORMATION ProcessInfo;
    SYSTEM_EXTENDED_THREAD_INFORMATION ThreadInfo;
};

struct _SYSTEM_PROCESSOR_POWER_INFORMATION // Size=72
{
    UCHAR CurrentFrequency; // Size=1 Offset=0
    UCHAR ThermalLimitFrequency; // Size=1 Offset=1
    UCHAR ConstantThrottleFrequency; // Size=1 Offset=2
    UCHAR DegradedThrottleFrequency; // Size=1 Offset=3
    UCHAR LastBusyFrequency; // Size=1 Offset=4
    UCHAR LastC3Frequency; // Size=1 Offset=5
    UCHAR LastAdjustedBusyFrequency; // Size=1 Offset=6
    UCHAR ProcessorMinThrottle; // Size=1 Offset=7
    UCHAR ProcessorMaxThrottle; // Size=1 Offset=8
    ULONG NumberOfFrequencies; // Size=4 Offset=12
    ULONG PromotionCount; // Size=4 Offset=16
    ULONG DemotionCount; // Size=4 Offset=20
    ULONG ErrorCount; // Size=4 Offset=24
    ULONG RetryCount; // Size=4 Offset=28
    ULONGLONG CurrentFrequencyTime; // Size=8 Offset=32
    ULONGLONG CurrentProcessorTime; // Size=8 Offset=40
    ULONGLONG CurrentProcessorIdleTime; // Size=8 Offset=48
    ULONGLONG LastProcessorTime; // Size=8 Offset=56
    ULONGLONG LastProcessorIdleTime; // Size=8 Offset=64
};

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX // Size=28
{
    PVOID Object; // Size=4 Offset=0
    ULONG UniqueProcessId; // Size=4 Offset=4
    ULONG HandleValue; // Size=4 Offset=8
    ULONG GrantedAccess; // Size=4 Offset=12
    USHORT CreatorBackTraceIndex; // Size=2 Offset=16
    USHORT ObjectTypeIndex; // Size=2 Offset=18
    ULONG HandleAttributes; // Size=4 Offset=20
    ULONG Reserved; // Size=4 Offset=24
};

struct _SYSTEM_HANDLE_INFORMATION_EX // Size=36
{
    ULONG NumberOfHandles; // Size=4 Offset=0
    ULONG Reserved; // Size=4 Offset=4
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1]; // Size=36 Offset=8
};

typedef struct _SYSTEM_BIGPOOL_ENTRY // Size=12
{
    PVOID VirtualAddress; // Size=4 Offset=0
    ULONG SizeInBytes; // Size=4 Offset=4
    UCHAR Tag[4]; // Size=4 Offset=8
} SYSTEM_BIGPOOL_ENTRY;

struct _SYSTEM_BIGPOOL_INFORMATION // Size=16
{
    ULONG Count; // Size=4 Offset=0
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1]; // Size=12 Offset=4
};

struct _SYSTEM_SESSION_POOLTAG_INFORMATION // Size=40
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG SessionId; // Size=4 Offset=4
    ULONG Count; // Size=4 Offset=8
    SYSTEM_POOLTAG TagInfo[1]; // Size=28 Offset=12
};

struct _SYSTEM_SESSION_MAPPED_VIEW_INFORMATION // Size=20
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG SessionId; // Size=4 Offset=4
    ULONG ViewFailures; // Size=4 Offset=8
    ULONG NumberOfBytesAvailable; // Size=4 Offset=12
    ULONG NumberOfBytesAvailableContiguous; // Size=4 Offset=16
};

typedef struct _HOTPATCH_HOOK_DESCRIPTOR // Size=40
{
    ULONGLONG TargetAddress; // Size=8 Offset=0
    ULONGLONG MappedAddress; // Size=8 Offset=8
    ULONG CodeOffset; // Size=4 Offset=16
    ULONG CodeSize; // Size=4 Offset=20
    ULONG OrigCodeOffset; // Size=4 Offset=24
    ULONG ValidationOffset; // Size=4 Offset=28
    ULONG ValidationSize; // Size=4 Offset=32
} HOTPATCH_HOOK_DESCRIPTOR;

struct _SYSTEM_HOTPATCH_CODE_INFORMATION_KERNEL_INFO // Size=4
{
    USHORT NameOffset; // Size=2 Offset=0
    USHORT NameLength; // Size=2 Offset=2
};

struct _SYSTEM_HOTPATCH_CODE_INFORMATION_USERMODE_INFO // Size=14
{
    USHORT NameOffset; // Size=2 Offset=0
    USHORT NameLength; // Size=2 Offset=2
    USHORT TargetNameOffset; // Size=2 Offset=4
    USHORT TargetNameLength; // Size=2 Offset=6
    USHORT ColdpatchImagePathOffset; // Size=2 Offset=8
    USHORT ColdpatchImagePathLength; // Size=2 Offset=10
    UCHAR PatchingFinished; // Size=1 Offset=12
};

struct _SYSTEM_HOTPATCH_CODE_INFORMATION_INJECTION_INFO // Size=24
{
    USHORT NameOffset; // Size=2 Offset=0
    USHORT NameLength; // Size=2 Offset=2
    USHORT TargetNameOffset; // Size=2 Offset=4
    USHORT TargetNameLength; // Size=2 Offset=6
    USHORT ColdpatchImagePathOffset; // Size=2 Offset=8
    USHORT ColdpatchImagePathLength; // Size=2 Offset=10
    ULONGLONG TargetProcess; // Size=8 Offset=16
};

struct _SYSTEM_HOTPATCH_CODE_INFORMATION_ATOMIC_SWAP // Size=24
{
    ULONGLONG ParentDirectory; // Size=8 Offset=0
    ULONGLONG ObjectHandle1; // Size=8 Offset=8
    ULONGLONG ObjectHandle2; // Size=8 Offset=16
};

struct _SYSTEM_HOTPATCH_CODE_INFORMATION_CODE_INFO // Size=48
{
    ULONG DescriptorsCount; // Size=4 Offset=0
    HOTPATCH_HOOK_DESCRIPTOR CodeDescriptors[1]; // Size=40 Offset=8
};

typedef enum _WATCHDOG_INFORMATION_CLASS
{
    WdInfoTimeoutValue = 0,
    WdInfoResetTimer = 1,
    WdInfoStopTimer = 2,
    WdInfoStartTimer = 3,
    WdInfoTriggerAction = 4,
    WdInfoState = 5
} WATCHDOG_INFORMATION_CLASS;

struct _SYSTEM_WATCHDOG_TIMER_INFORMATION // Size=8
{
    WATCHDOG_INFORMATION_CLASS WdInfoClass; // Size=4 Offset=0
    ULONG DataValue; // Size=4 Offset=4
};

struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_PROCESSOR_CORE // Size=1
{
    UCHAR Flags; // Size=1 Offset=0
};

struct _SYSTEM_LOGICAL_PROCESSOR_INFORMATION_NUMA_CODE // Size=4
{
    ULONG NodeNumber; // Size=4 Offset=0
};



typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION
{
    SystemFirmwareTable_Enumerate = 0,
    SystemFirmwareTable_Get = 1
} SYSTEM_FIRMWARE_TABLE_ACTION;

struct _SYSTEM_FIRMWARE_TABLE_INFORMATION // Size=20
{
    ULONG ProviderSignature; // Size=4 Offset=0
    SYSTEM_FIRMWARE_TABLE_ACTION Action; // Size=4 Offset=4
    ULONG TableID; // Size=4 Offset=8
    ULONG TableBufferLength; // Size=4 Offset=12
    UCHAR TableBuffer[1]; // Size=1 Offset=16
};

struct _SYSTEM_VERIFIER_TRIAGE_INFORMATION // Size=544
{
    ULONG ActionTaken; // Size=4 Offset=0
    ULONG CrashData[5]; // Size=20 Offset=4
    ULONG VerifierMode; // Size=4 Offset=24
    ULONG VerifierFlags; // Size=4 Offset=28
    WCHAR VerifierTargets[256]; // Size=512 Offset=32
};

struct _SYSTEM_MEMORY_LIST_INFORMATION // Size=88
{
    ULONG ZeroPageCount; // Size=4 Offset=0
    ULONG FreePageCount; // Size=4 Offset=4
    ULONG ModifiedPageCount; // Size=4 Offset=8
    ULONG ModifiedNoWritePageCount; // Size=4 Offset=12
    ULONG BadPageCount; // Size=4 Offset=16
    ULONG PageCountByPriority[8]; // Size=32 Offset=20
    ULONG RepurposedPagesByPriority[8]; // Size=32 Offset=52
    ULONG ModifiedPageCountPageFile; // Size=4 Offset=84
};

struct _SYSTEM_THREAD_CID_PRIORITY_INFORMATION // Size=12
{
    CLIENT_ID ClientId; // Size=8 Offset=0
    LONG Priority; // Size=4 Offset=8
};

struct _SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION // Size=8
{
    ULONGLONG CycleTime; // Size=8 Offset=0
};

typedef struct _SYSTEM_VERIFIER_ISSUE // Size=16
{
    ULONG IssueType; // Size=4 Offset=0
    PVOID Address; // Size=4 Offset=4
    ULONG Parameters[2]; // Size=8 Offset=8
} SYSTEM_VERIFIER_ISSUE;

struct _SYSTEM_VERIFIER_CANCELLATION_INFORMATION // Size=2068
{
    ULONG CancelProbability; // Size=4 Offset=0
    ULONG CancelThreshold; // Size=4 Offset=4
    ULONG CompletionThreshold; // Size=4 Offset=8
    ULONG CancellationVerifierDisabled; // Size=4 Offset=12
    ULONG AvailableIssues; // Size=4 Offset=16
    SYSTEM_VERIFIER_ISSUE Issues[128]; // Size=2048 Offset=20
};

struct _SYSTEM_REF_TRACE_INFORMATION // Size=20
{
    UCHAR TraceEnable; // Size=1 Offset=0
    UCHAR TracePermanent; // Size=1 Offset=1
    UNICODE_STRING TraceProcessName; // Size=8 Offset=4
    UNICODE_STRING TracePoolTags; // Size=8 Offset=12
};

struct _SYSTEM_SPECIAL_POOL_INFORMATION // Size=8
{
    ULONG PoolTag; // Size=4 Offset=0
    ULONG Flags; // Size=4 Offset=4
};

struct _SYSTEM_PROCESS_ID_INFORMATION // Size=12
{
    PVOID ProcessId; // Size=4 Offset=0
    UNICODE_STRING ImageName; // Size=8 Offset=4
};


struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION // Size=32
{
    GUID BootIdentifier; // Size=16 Offset=0
    FIRMWARE_TYPE FirmwareType; // Size=4 Offset=16
    ULONGLONG BootFlags; // Size=8 Offset=24
};

struct _SYSTEM_VERIFIER_INFORMATION_EX // Size=36
{
    ULONG VerifyMode; // Size=4 Offset=0
    ULONG OptionChanges; // Size=4 Offset=4
    UNICODE_STRING PreviousBucketName; // Size=8 Offset=8
    ULONG IrpCancelTimeoutMsec; // Size=4 Offset=16
    ULONG VerifierExtensionEnabled; // Size=4 Offset=20
    ULONG Reserved[3]; // Size=12 Offset=24
};

struct _SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION // Size=8
{
    ULONG FlagsToEnable; // Size=4 Offset=0
    ULONG FlagsToDisable; // Size=4 Offset=4
};

struct _SYSTEM_PREFETCH_PATCH_INFORMATION // Size=4
{
    ULONG PrefetchPatchCount; // Size=4 Offset=0
};

struct _SYSTEM_VERIFIER_FAULTS_INFORMATION // Size=24
{
    ULONG Probability; // Size=4 Offset=0
    ULONG MaxProbability; // Size=4 Offset=4
    UNICODE_STRING PoolTags; // Size=8 Offset=8
    UNICODE_STRING Applications; // Size=8 Offset=16
};

struct _SYSTEM_SYSTEM_PARTITION_INFORMATION // Size=8
{
    UNICODE_STRING SystemPartition; // Size=8 Offset=0
};

struct _SYSTEM_SYSTEM_DISK_INFORMATION // Size=8
{
    UNICODE_STRING SystemDisk; // Size=8 Offset=0
};

struct _SYSTEM_CODEINTEGRITY_INFORMATION // Size=8
{
    ULONG Length; // Size=4 Offset=0
    ULONG CodeIntegrityOptions; // Size=4 Offset=4
};

struct _SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION // Size=4
{
    ULONG Operation; // Size=4 Offset=0
};


struct _SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // Size=36
{
    PVOID KeyHandle; // Size=4 Offset=0
    PUNICODE_STRING ValueNamePointer; // Size=4 Offset=4
    ULONG_PTR RequiredLengthPointer; // Size=4 Offset=8
    PUCHAR Buffer; // Size=4 Offset=12
    ULONG BufferLength; // Size=4 Offset=16
    ULONG Type; // Size=4 Offset=20
    PUCHAR AppendBuffer; // Size=4 Offset=24
    ULONG AppendBufferLength; // Size=4 Offset=28
    UCHAR CreateIfDoesntExist; // Size=1 Offset=32
    UCHAR TruncateExistingValue; // Size=1 Offset=33
};

struct _SYSTEM_VHD_BOOT_INFORMATION // Size=12
{
    UCHAR OsDiskIsVhd; // Size=1 Offset=0
    ULONG OsVhdFilePathOffset; // Size=4 Offset=4
    WCHAR OsVhdParentVolume[1]; // Size=2 Offset=8
};

struct _SYSTEM_ERROR_PORT_TIMEOUTS // Size=8
{
    ULONG StartTimeout; // Size=4 Offset=0
    ULONG CommTimeout; // Size=4 Offset=4
};

struct _SYSTEM_LOW_PRIORITY_IO_INFORMATION // Size=40
{
    ULONG LowPriReadOperations; // Size=4 Offset=0
    ULONG LowPriWriteOperations; // Size=4 Offset=4
    ULONG KernelBumpedToNormalOperations; // Size=4 Offset=8
    ULONG LowPriPagingReadOperations; // Size=4 Offset=12
    ULONG KernelPagingReadsBumpedToNormal; // Size=4 Offset=16
    ULONG LowPriPagingWriteOperations; // Size=4 Offset=20
    ULONG KernelPagingWritesBumpedToNormal; // Size=4 Offset=24
    ULONG BoostedIrpCount; // Size=4 Offset=28
    ULONG BoostedPagingIrpCount; // Size=4 Offset=32
    ULONG BlanketBoostCount; // Size=4 Offset=36
};

struct _SYSTEM_VERIFIER_COUNTERS_INFORMATION // Size=168
{
    SYSTEM_VERIFIER_INFORMATION Legacy; // Size=104 Offset=0
    ULONG RaiseIrqls; // Size=4 Offset=104
    ULONG AcquireSpinLocks; // Size=4 Offset=108
    ULONG SynchronizeExecutions; // Size=4 Offset=112
    ULONG AllocationsWithNoTag; // Size=4 Offset=116
    ULONG AllocationsFailed; // Size=4 Offset=120
    ULONG AllocationsFailedDeliberately; // Size=4 Offset=124
    ULONG LockedBytes; // Size=4 Offset=128
    ULONG PeakLockedBytes; // Size=4 Offset=132
    ULONG MappedLockedBytes; // Size=4 Offset=136
    ULONG PeakMappedLockedBytes; // Size=4 Offset=140
    ULONG MappedIoSpaceBytes; // Size=4 Offset=144
    ULONG PeakMappedIoSpaceBytes; // Size=4 Offset=148
    ULONG PagesForMdlBytes; // Size=4 Offset=152
    ULONG PeakPagesForMdlBytes; // Size=4 Offset=156
    ULONG ContiguousMemoryBytes; // Size=4 Offset=160
    ULONG PeakContiguousMemoryBytes; // Size=4 Offset=164
};

struct _SYSTEM_ACPI_AUDIT_INFORMATION // Size=8
{
    ULONG RsdpCount; // Size=4 Offset=0
    struct
    {
        ULONG SameRsdt : 1; // Size=4 Offset=4 BitOffset=0 BitCount=1
        ULONG SlicPresent : 1; // Size=4 Offset=4 BitOffset=1 BitCount=1
        ULONG SlicDifferent : 1; // Size=4 Offset=4 BitOffset=2 BitCount=1
    };
};

struct _SYSTEM_BASIC_PERFORMANCE_INFORMATION // Size=16
{
    ULONG AvailablePages; // Size=4 Offset=0
    ULONG CommittedPages; // Size=4 Offset=4
    ULONG CommitLimit; // Size=4 Offset=8
    ULONG PeakCommitment; // Size=4 Offset=12
};

typedef struct _QUERY_PERFORMANCE_COUNTER_FLAGS // Size=4
{
    struct
    {
        ULONG KernelTransition : 1; // Size=4 Offset=0 BitOffset=0 BitCount=1
        ULONG Reserved : 31; // Size=4 Offset=0 BitOffset=1 BitCount=31
    };
    ULONG ul; // Size=4 Offset=0
} QUERY_PERFORMANCE_COUNTER_FLAGS;

struct _SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // Size=12
{
    ULONG Version; // Size=4 Offset=0
    QUERY_PERFORMANCE_COUNTER_FLAGS Flags; // Size=4 Offset=4
    QUERY_PERFORMANCE_COUNTER_FLAGS ValidFlags; // Size=4 Offset=8
};

struct _SYSTEM_SESSION_BIGPOOL_INFORMATION // Size=24
{
    ULONG NextEntryOffset; // Size=4 Offset=0
    ULONG SessionId; // Size=4 Offset=4
    ULONG Count; // Size=4 Offset=8
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1]; // Size=12 Offset=12
};

typedef enum _SYSTEM_PIXEL_FORMAT
{
    SystemPixelFormatUnknown = 0,
    SystemPixelFormatR8G8B8 = 1,
    SystemPixelFormatR8G8B8X8 = 2,
    SystemPixelFormatB8G8R8 = 3,
    SystemPixelFormatB8G8R8X8 = 4
} SYSTEM_PIXEL_FORMAT;

struct _SYSTEM_BOOT_GRAPHICS_INFORMATION // Size=32
{
    LARGE_INTEGER FrameBuffer; // Size=8 Offset=0
    ULONG Width; // Size=4 Offset=8
    ULONG Height; // Size=4 Offset=12
    ULONG PixelStride; // Size=4 Offset=16
    ULONG Flags; // Size=4 Offset=20
    SYSTEM_PIXEL_FORMAT Format; // Size=4 Offset=24
};

typedef struct _PEBS_DS_SAVE_AREA // Size=96
{
    ULONGLONG BtsBufferBase; // Size=8 Offset=0
    ULONGLONG BtsIndex; // Size=8 Offset=8
    ULONGLONG BtsAbsoluteMaximum; // Size=8 Offset=16
    ULONGLONG BtsInterruptThreshold; // Size=8 Offset=24
    ULONGLONG PebsBufferBase; // Size=8 Offset=32
    ULONGLONG PebsIndex; // Size=8 Offset=40
    ULONGLONG PebsAbsoluteMaximum; // Size=8 Offset=48
    ULONGLONG PebsInterruptThreshold; // Size=8 Offset=56
    ULONGLONG PebsCounterReset0; // Size=8 Offset=64
    ULONGLONG PebsCounterReset1; // Size=8 Offset=72
    ULONGLONG PebsCounterReset2; // Size=8 Offset=80
    ULONGLONG PebsCounterReset3; // Size=8 Offset=88
} PEBS_DS_SAVE_AREA;

typedef struct _PROCESSOR_PROFILE_CONTROL_AREA // Size=96
{
    PEBS_DS_SAVE_AREA PebsDsSaveArea; // Size=96 Offset=0
} *PPROCESSOR_PROFILE_CONTROL_AREA;

struct _SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA // Size=8
{
    PPROCESSOR_PROFILE_CONTROL_AREA ProcessorProfileControlArea; // Size=4 Offset=0
    UCHAR Allocate; // Size=1 Offset=4
};

struct _SYSTEM_ENTROPY_TIMING_INFORMATION // Size=12
{
    PVOID EntropyRoutine; // Size=4 Offset=0 VOID (* EntropyRoutine)(PVOID,ULONG)
    PVOID InitializationRoutine; // Size=4 Offset=4 VOID ( * InitializationRoutine)(PVOID,ULONG,PVOID)
    PVOID InitializationContext; // Size=4 Offset=8
};

struct _SYSTEM_CONSOLE_INFORMATION // Size=4
{
    ULONG DriverLoaded : 1; // Size=4 Offset=0 BitOffset=0 BitCount=1
    ULONG Spare : 31; // Size=4 Offset=0 BitOffset=1 BitCount=31
};

struct _SYSTEM_PLATFORM_BINARY_INFORMATION // Size=24
{
    ULONGLONG PhysicalAddress; // Size=8 Offset=0
    PVOID HandoffBuffer; // Size=4 Offset=8
    PVOID CommandLineBuffer; // Size=4 Offset=12
    ULONG HandoffBufferSize; // Size=4 Offset=16
    ULONG CommandLineBufferSize; // Size=4 Offset=20
};

struct _SYSTEM_DEVICE_DATA_INFORMATION // Size=28
{
    UNICODE_STRING DeviceId; // Size=8 Offset=0
    UNICODE_STRING DataName; // Size=8 Offset=8
    ULONG DataType; // Size=4 Offset=16
    ULONG DataBufferLength; // Size=4 Offset=20
    PVOID DataBuffer; // Size=4 Offset=24
};

typedef struct _PHYSICAL_CHANNEL_RUN // Size=32
{
    ULONG NodeNumber; // Size=4 Offset=0
    ULONG ChannelNumber; // Size=4 Offset=4
    ULONGLONG BasePage; // Size=8 Offset=8
    ULONGLONG PageCount; // Size=8 Offset=16
    ULONG Flags; // Size=4 Offset=24
} PHYSICAL_CHANNEL_RUN;

struct _SYSTEM_MEMORY_TOPOLOGY_INFORMATION // Size=48
{
    ULONGLONG NumberOfRuns; // Size=8 Offset=0
    ULONG NumberOfNodes; // Size=4 Offset=8
    ULONG NumberOfChannels; // Size=4 Offset=12
    PHYSICAL_CHANNEL_RUN Run[1]; // Size=32 Offset=16
};

struct _SYSTEM_MEMORY_CHANNEL_INFORMATION // Size=40
{
    ULONG ChannelNumber; // Size=4 Offset=0
    ULONG ChannelHeatIndex; // Size=4 Offset=4
    ULONGLONG TotalPageCount; // Size=8 Offset=8
    ULONGLONG ZeroPageCount; // Size=8 Offset=16
    ULONGLONG FreePageCount; // Size=8 Offset=24
    ULONGLONG StandbyPageCount; // Size=8 Offset=32
};

struct _SYSTEM_BOOT_LOGO_INFORMATION // Size=8
{
    ULONG Flags; // Size=4 Offset=0
    ULONG BitmapOffset; // Size=4 Offset=4
};

struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // Size=72
{
    LARGE_INTEGER IdleTime; // Size=8 Offset=0
    LARGE_INTEGER KernelTime; // Size=8 Offset=8
    LARGE_INTEGER UserTime; // Size=8 Offset=16
    LARGE_INTEGER DpcTime; // Size=8 Offset=24
    LARGE_INTEGER InterruptTime; // Size=8 Offset=32
    ULONG InterruptCount; // Size=4 Offset=40
    ULONG Spare0; // Size=4 Offset=44
    LARGE_INTEGER AvailableTime; // Size=8 Offset=48
    LARGE_INTEGER Spare1; // Size=8 Offset=56
    LARGE_INTEGER Spare2; // Size=8 Offset=64
};

struct _SYSTEM_SECUREBOOT_POLICY_INFORMATION // Size=24
{
    GUID PolicyPublisher; // Size=16 Offset=0
    ULONG PolicyVersion; // Size=4 Offset=16
    ULONG PolicyOptions; // Size=4 Offset=20
};

struct _SYSTEM_SECUREBOOT_INFORMATION // Size=2
{
    UCHAR SecureBootEnabled; // Size=1 Offset=0
    UCHAR SecureBootCapable; // Size=1 Offset=1
};

struct _SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION // Size=1
{
    UCHAR EfiLauncherEnabled; // Size=1 Offset=0
};



//  ------------------------------------------------------------ -------------

typedef struct _OBJECT_TYPE_INFORMATION
{
    UNICODE_STRING Name;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG TotalPagedPoolUsage;
    ULONG TotalNonPagedPoolUsage;
    ULONG TotalNamePoolUsage;
    ULONG TotalHandleTableUsage;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    ULONG HighWaterPagedPoolUsage;
    ULONG HighWaterNonPagedPoolUsage;
    ULONG HighWaterNamePoolUsage;
    ULONG HighWaterHandleTableUsage;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccess;
    BOOLEAN SecurityRequired;
    BOOLEAN MaintainHandleCount;
    USHORT MaintainTypeList;
    POOL_TYPE PoolType;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

//  ------------------------------------------------------------ -------------



typedef LONG NTSTATUS;


typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;

		PVOID Pointer;
	};

	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;


typedef void (WINAPI* PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, DWORD);


typedef LONG TDI_STATUS;

typedef PVOID CONNECTION_CONTEXT; ; // connection context


typedef struct _TDI_REQUEST
{
	union
	{
		HANDLE AddressHandle;

		CONNECTION_CONTEXT ConnectionContext;

		HANDLE ControlChannel;
	} Handle;


	PVOID RequestNotifyObject;

	PVOID RequestContext;

	TDI_STATUS TdiStatus;
} TDI_REQUEST, *PTDI_REQUEST;


typedef struct _TDI_CONNECTION_INFORMATION
{
	LONG UserDataLength; // length of user data buffer

	PVOID UserData; // pointer to user data buffer

	LONG OptionsLength; // length of following buffer

	PVOID Options; //  pointer to buffer containing options

	LONG RemoteAddressLength; // length of following buffer

	PVOID RemoteAddress; // buffer containing the remote address
} TDI_CONNECTION_INFORMATION, *PTDI_CONNECTION_INFORMATION;


typedef struct _TDI_REQUEST_QUERY_INFORMATION
{
	TDI_REQUEST Request;

	ULONG QueryType; //  class of information to be queried.

	PTDI_CONNECTION_INFORMATION RequestConnectionInformation;
} TDI_REQUEST_QUERY_INFORMATION, *PTDI_REQUEST_QUERY_INFORMATION;


#define  TDI_QUERY_ADDRESS_INFO          0x00000003

#define  IOCTL_TDI_QUERY_INFORMATION       CTL_CODE(FILE_DEVICE_TRANSPORT, 4, METHOD_OUT_DIRECT, FILE_ANY_ACCESS)


typedef VOID* POBJECT;


typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG          Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;


typedef UNICODE_STRING* POBJECT_NAME_INFORMATION;


#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

#define  STATUS_SUCCESS                 ((NTSTATUS)0x00000000L)
#define  STATUS_INFO_LENGTH_MISMATCH    ((NTSTATUS)0xC0000004L)
#define  STATUS_BUFFER_OVERFLOW         ((NTSTATUS)0x80000005L)

//  ------------------------------------------------------------ -------------


typedef NTSTATUS (NTAPI* tNtQuerySystemInformation)(
	_SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS (NTAPI* tNtQueryObject)(
	HANDLE                   Handle,
    DWORD                    ObjectInformationClass,
	PVOID                    ObjectInformation,
	ULONG                    ObjectInformationLength,
	PULONG                   ReturnLength
);

typedef NTSTATUS (NTAPI* tNtDeviceIoControlFile)(
    HANDLE           FileHandle,
    HANDLE           Event,
    PIO_APC_ROUTINE  ApcRoutine,
    PVOID            ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG            IoControlCode,
    PVOID            InputBuffer,
    ULONG            InputBufferLength,
    PVOID            OutputBuffer,
    ULONG            OutputBufferLength
);

typedef NTSTATUS (NTAPI* tNtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
);

LPWSTR GetObjectName(HANDLE hObject);

LPWSTR GetObjectTypeName(HANDLE hObject);
