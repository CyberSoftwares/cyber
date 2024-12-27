#pragma once
#include "includes.hpp"
#include <atlstr.h>
#include <stdlib.h>
#include <string>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <TlHelp32.h>
#include "callproxy.h"
#include <algorithm>


typedef struct _TransferData
{
    HANDLE process_id;
    void* remote_address;
    void* local_buffer;
    SIZE_T transfer_size;
    SIZE_T bytes_transferred;
} TransferData;

typedef struct _MemoryQueryData
{
    HANDLE process_id;
    void* query_address;
    MEMORY_BASIC_INFORMATION memory_info;
    NTSTATUS status;
} MemoryQueryData;

static constexpr ULONG init_command = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x890, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
static constexpr ULONG read_command = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x891, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
static constexpr ULONG write_command = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x892, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
static constexpr ULONG query_command = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x893, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);


namespace SysHelper
{
    class DriverInteraction
    {
    private:
        std::vector<MEMORY_BASIC_INFORMATION64> memory_blocks;
        bool optimize_memory_data = false;

        HANDLE driver_handle = INVALID_HANDLE_VALUE;

        inline uintptr_t FetchModuleBaseAddress(DWORD process_id, const char* module_name)
        {
            uintptr_t module_base = 0;
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
            if (snapshot != INVALID_HANDLE_VALUE)
            {
                MODULEENTRY32 module_entry;
                module_entry.dwSize = sizeof(module_entry);
                if (Module32First(snapshot, &module_entry))
                {
                    do
                    {
                        if (!_stricmp(module_entry.szModule, module_name))
                        {
                            module_base = reinterpret_cast<uintptr_t>(module_entry.modBaseAddr);
                            break;
                        }
                    } while (Module32Next(snapshot, &module_entry));
                }
                CloseHandle(snapshot);
            }
            return module_base;
        }

    public:
        HANDLE process_handle = 0;
        uint64_t game_base_address = 0;
        uint64_t controller_address = 0;
        HWND main_window_handle = NULL;

    public:

        inline bool InitializeSystem()
        {
            DWORD process_id = 0;
            main_window_handle = FindWindowA("", NULL);
            if (!main_window_handle)
                return false;

            GetWindowThreadProcessId(main_window_handle, &process_id);
            if (!process_id)
                return false;

            process_handle = reinterpret_cast<HANDLE>(process_id);
            game_base_address = FetchModuleBaseAddress(process_id, "");
            return game_base_address != 0;
        }

        inline bool ConnectDriver()
        {
            driver_handle = CreateFileA(
                R"(\\.\DRIVER)",
                GENERIC_READ | GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                NULL
            );

            if (driver_handle == INVALID_HANDLE_VALUE)
                return false;

            TransferData init_request = { 0 };
            init_request.process_id = process_handle;

            DWORD returned_bytes = 0;
            BOOL result = DeviceIoControl(
                driver_handle,
                init_command,
                &init_request, sizeof(init_request),
                &init_request, sizeof(init_request),
                &returned_bytes,
                nullptr
            );
            if (!result)
            {
                CloseHandle(driver_handle);
                driver_handle = INVALID_HANDLE_VALUE;
                return false;
            }
            return true;
        }

        template <typename WriteType>
        __forceinline bool WriteMemory(DWORD_PTR address, WriteType value)
        {
            if (driver_handle == INVALID_HANDLE_VALUE || !process_handle)
                return false;

            TransferData write_request = { 0 };
            write_request.process_id = process_handle;
            write_request.remote_address = reinterpret_cast<void*>(address);
            write_request.local_buffer = &value;
            write_request.transfer_size = sizeof(WriteType);

            DWORD returned_bytes = 0;
            BOOL result = DeviceIoControl(
                driver_handle,
                write_command,
                &write_request,
                sizeof(write_request),
                &write_request,
                sizeof(write_request),
                &returned_bytes,
                nullptr
            );
            return (result && write_request.bytes_transferred == sizeof(WriteType));
        }

        template <typename ReadType>
        __forceinline ReadType ReadMemory(DWORD_PTR address)
        {
            ReadType buffer{};
            if (driver_handle == INVALID_HANDLE_VALUE || !process_handle)
                return buffer;

            TransferData read_request = { 0 };
            read_request.process_id = process_handle;
            read_request.remote_address = reinterpret_cast<void*>(address);
            read_request.local_buffer = &buffer;
            read_request.transfer_size = sizeof(ReadType);

            DWORD returned_bytes = 0;
            BOOL result = DeviceIoControl(
                driver_handle,
                read_command,
                &read_request,
                sizeof(read_request),
                &read_request,
                sizeof(read_request),
                &returned_bytes,
                nullptr
            );
            return result ? buffer : ReadType{};
        }

        __forceinline SIZE_T QueryMemory(DWORD_PTR address, MEMORY_BASIC_INFORMATION* memory_info, SIZE_T info_size)
        {
            if (driver_handle == INVALID_HANDLE_VALUE || !process_handle || !memory_info)
                return 0;

            MemoryQueryData query_data = { 0 };
            query_data.process_id = process_handle;
            query_data.query_address = reinterpret_cast<void*>(address);

            DWORD returned_bytes = 0;
            BOOL result = DeviceIoControl(
                driver_handle,
                query_command,
                &query_data,
                sizeof(query_data),
                &query_data,
                sizeof(query_data),
                &returned_bytes,
                nullptr
            );

            if (!result || query_data.status <= 0)
                return 0;

            SIZE_T copy_size = std::min(info_size, sizeof(MEMORY_BASIC_INFORMATION));
            memcpy(memory_info, &query_data.memory_info, copy_size);
            return copy_size;
        }
    };

    inline auto SystemHelper = std::make_unique<DriverInteraction>();
}
