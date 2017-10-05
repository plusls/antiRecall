#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>

using namespace std;

bool getProcessIDList(const string &processName, vector<DWORD> &processIDList) //获得进程id 并加入processIDList的尾部
{
    HANDLE pHandle;
    PROCESSENTRY32 processData;
    pHandle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0x0); //获得进程快照句柄

    if (pHandle == INVALID_HANDLE_VALUE)
        return false;

    processData.dwSize = sizeof(PROCESSENTRY32); //必须调用 否则调用 Process32First 会失败

    if (Process32First(pHandle, &processData) == false) //初始化
        return false;

    do
    {
        //printf("processName:%s %s\n", processName.c_str(), processData.szExeFile);
        if (processName == processData.szExeFile)
            processIDList.push_back(processData.th32ProcessID);
    } while (Process32Next(pHandle, &processData));

    CloseHandle(pHandle);
    return true;
}

pair<BYTE *, DWORD> getModuleAddr(DWORD dwPID, const string &moduleName)
{
    pair<BYTE *, DWORD> ret(NULL, 0);
    HANDLE mHandle;
    MODULEENTRY32 moduleData;
    mHandle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID); //获得模块快照句柄

    if (mHandle == INVALID_HANDLE_VALUE)
        return ret;

    moduleData.dwSize = sizeof(MODULEENTRY32); //必须设置 否则调用 Module32First 会失败

    if (Module32First(mHandle, &moduleData) == false)
        return ret;

    do
    {
        if (moduleName == moduleData.szModule)
        {

            ret.first = moduleData.modBaseAddr;
            ret.second = moduleData.modBaseSize;
            //printf("%s %x %x\n", moduleData.szModule, moduleData.modBaseAddr, moduleData.modBaseSize);
            return ret;
        }
    } while (Module32Next(mHandle, &moduleData));

    return ret;
}

bool modifyRecall(DWORD dwPID, BYTE *startAddr, DWORD size)
{
    const char *user = "\x81\x7d\x0c\x8a\x00",
               *group = "\x80\x7D\xFF\x11\x0f";
    size_t dataLen = 5;

    BYTE *userAddr, *groupAddr;
    char memoryToWrite;

    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, false, dwPID);
    if (pHandle == INVALID_HANDLE_VALUE)
        return false;

    BYTE *buffer = new BYTE[size];

    if (ReadProcessMemory(pHandle, startAddr, buffer, size, NULL) == false)
        return false;

    for (size_t i = 0; i <= (size - dataLen); ++i)
    {
        if (memcmp(buffer + i, user, dataLen) == 0)
        {
            userAddr = startAddr + i - 5;
            if ((char)buffer[i - 5] == '\x85')
                memoryToWrite = '\x84';
            else
                memoryToWrite = '\x85';
        }

        if (memcmp(buffer + i, group, dataLen) == 0)
        {
            groupAddr = startAddr + i + 5;
        }
    }
    //printf("%p %p\n", userAddr, groupAddr);
    if (WriteProcessMemory(pHandle, userAddr, &memoryToWrite, 1, NULL) == false)
        return false;

    if (WriteProcessMemory(pHandle, groupAddr, &memoryToWrite, 1, NULL) == false)
        return false;

    if (memoryToWrite == '\x84')
        printf("Anti recall success! PID:%u\n", dwPID);
    else
        printf("Close anti recall success! PID:%u\n", dwPID);
        
    CloseHandle(pHandle);

    return true;
}

int main()
{
    vector<DWORD> processIDList;
    puts("QQ anti recall.By:plusls");
    system("pause");
    if (getProcessIDList("TIM.exe", processIDList) && getProcessIDList("QQ.exe", processIDList))
    {
        if (processIDList.size() == 0)
        {
            puts("Can't find QQ or TIM");
            system("pause");
            exit(0);
        }
    }
    else
    {
        puts("Get process snapshot faild");
        system("pause");
        exit(0);
    }
    puts("Find process success!");
    for (auto dwPID : processIDList)
    {
        pair<BYTE *, DWORD> moduleData = getModuleAddr(dwPID, "IM.dll");
        if (modifyRecall(dwPID, moduleData.first, moduleData.second) == false)
        {
            puts("Modify recall faild");
            system("pause");
            exit(0);
        }
    }
    system("pause");
    exit(0);
    return 0;
}
