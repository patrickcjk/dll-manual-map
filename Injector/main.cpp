#include <windows.h>
#include <Lmcons.h>
#include <iostream>

#include "stdafx.h"
#include "injector.h"
#include "Shlobj.h"
#include "Shlobj_core.h"

int main()
{
    try 
    {
        /* Get username */
        char name[UNLEN + 1];
        DWORD size = sizeof(name);

        if (GetUserNameA(&name[0], &size))
        {
            std::cout << INFO << "Good morning, " << name << "!" << std::endl;
        }
        else
        {
            std::cout << INFO << "Good morning!" << std::endl;
        }

        /* Get System directory */
        char _path[MAX_PATH + 1];
        if (!SHGetSpecialFolderPath(NULL, _path, CSIDL_SYSTEM, FALSE))
        {
            std::cout << ERROR << "OOPS! We ran into some problems... #484" << std::endl;
            std::cin.get();
            return -1;
        }

        std::string path = std::string(_path) + "\\" + VULNERABLE_PROCESS;

        STARTUPINFO si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        /* Create our vulnerable process */
        BOOL status = CreateProcessA(path.c_str(), NULL, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
        if (!status)
        {
            std::cout << ERROR << "OOPS! We ran into some problems... #485" << std::endl;
            std::cin.get();
            return -1;
        }

        /* Create process */
        HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
        //HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
        if (!process_handle)
        {
            std::cout << ERROR << "OOPS! We ran into some problems... #486" << std::endl;
            std::cin.get();
            return -1;
        }

        /* Map dll */
        bool status_map = ManualMap(process_handle, BINARY_PATH);
        CloseHandle(process_handle);

        if (!status_map)
        {
            std::cout << ERROR << "OOPS! We ran into some problems... #487" << std::endl;
            std::cin.get();
            return -1;
        }

        std::cout << SUCCESS << "Done! Your program should start now..." << std::endl;
    }
    catch (std::exception const& e)
    {
        std::cout << ERROR << "OOPS! An exception occured :(" << std::endl;
        std::cout << ERROR << e.what() << std::endl;
        std::cin.get();
        return -1;
    }

    //std::cout << INFO << "Goodbye! This window will close in 5 seconds" << std::endl;
    //Sleep(5000);

    std::cin.get();
    return 0;
}