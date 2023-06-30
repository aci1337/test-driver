# test-driver

This driver will allow the user, to:

1. Block user mouse movment

```    
    blockMouse = TRUE;

        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -10 * 1000 * 10000LL; 
        KeDelayExecutionThread(KernelMode, FALSE, &dueTime);

        blockMouse = FALSE;
```

**For this we will use mice_hook, UnblockMouseDpcRoutine, and much more... Functions being avalabile at lines 30724+**

2. Block hotkeys

For that we will use, **IOCTL_BLOCK_HOTKEYS** this will use PsSetCreateProcessNotifyRoutineEx, function to block the user hotkeys (keyboard access)
```
        PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
```

3. Download files from the driver

For this, we will be using **BYTES** getting the bytes, is simple use HxD or other tools! 
For this we will need a "path" and the "bytes" themself (i've provided an example below)

**BYTES:**
```
unsigned char byteex[11] = {
	0x6A, 0x75, 0x73, 0x74, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74
};
```

**TEST:**
```
        OBJECT_ATTRIBUTES objAttribs;
        UNICODE_STRING uniFileName;
        IO_STATUS_BLOCK ioStatusBlock;
        HANDLE hFile = NULL;
        OBJECT_ATTRIBUTES awert;
        UNICODE_STRING aedfb;
        IO_STATUS_BLOCK aedfbn;
        HANDLE ass = NULL;
     RtlZeroMemory(&objAttribs, sizeof(OBJECT_ATTRIBUTES));
     RtlInitUnicodeString(&uniFileName, L"\\DosDevices\\C:\\ProgramData\\test.txt");
     InitializeObjectAttributes(&objAttribs, &uniFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
     NTSTATUS status = ZwCreateFile(&hFile, GENERIC_WRITE | SYNCHRONIZE, &objAttribs, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

     if (NT_SUCCESS(status)) {
     	ULONG bytesWritten = 0;
     	status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, rawDatae, sizeof(rawDatae), NULL, NULL);
     	if (NT_SUCCESS(status)) {
     		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 0);
     	}
     	else {
     		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 0);
     	}

     	ZwClose(hFile);
     }
     else {
     }
```

**Disclaimer: This won't help you from getting "byte dumped", you can just simply dump the .sys file and done + you will can see the path due to RtlInitUnicodeString.**

4. Disable a OB Callback

This isn't ready yet!

5. Read Virtual Memory

We can read virtual memory using **IOCTL_READ_MEMORY** and copy_memorys

``` 
        pk_rw_request in = (pk_rw_request)irp->AssociatedIrp.SystemBuffer;
        PEPROCESS target_proc;
        HANDLE pid_handle = (HANDLE)(ULONG_PTR)in->pid;
        NTSTATUS status = PsLookupProcessByProcessId(pid_handle, &target_proc);
        if (NT_SUCCESS(status)) {
            PVOID src_ptr = (PVOID)(ULONG_PTR)in->src;
            PVOID dst_ptr = (PVOID)(ULONG_PTR)in->dst;
            status = copy_memorys(PsGetCurrentProcess(), target_proc, src_ptr, dst_ptr, in->size);

            ObDereferenceObjectWithTag(target_proc, 'tMac');
        }

        info_size = sizeof(k_rw_request);
```

6. Write Virtual Memory

```
pk_rw_request in = (pk_rw_request)irp->AssociatedIrp.SystemBuffer;
        PEPROCESS target_proc;
        HANDLE pid_handle = (HANDLE)(ULONG_PTR)in->pid;
        NTSTATUS status = PsLookupProcessByProcessId(pid_handle, &target_proc);
        if (NT_SUCCESS(status)) {
            if (in->src) {
                PVOID src_ptr = (PVOID)(ULONG_PTR)in->src;
                PVOID dst_ptr = (PVOID)(ULONG_PTR)in->dst;
                write_mem(in->pid, src_ptr, dst_ptr, in->size);
            }

            ObDereferenceObjectWithTag(target_proc, 'tMea');
        }
        info_size = sizeof(k_rw_request);```
