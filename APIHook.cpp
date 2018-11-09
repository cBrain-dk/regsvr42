/******************************************************************************
Module:  APIHook.cpp
Notices: Copyright (c) 2008 Jeffrey Richter & Christophe Nasarre
******************************************************************************/

#include "stdafx.h"
#include "CmnHdr.h"
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")

#include "APIHook.h"
#include "mhook.h"
#include "Toolhelp.h"
#include <StrSafe.h>


/////////////////////////////////////////////////////////////////////////////////

CAPIHook::CAPIHook(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook) {

   // Note: the function can be hooked only if the exporting module 
   //       is already loaded. A solution could be to store the function
   //       name as a member; then, in the hooked LoadLibrary* handlers, parse
   //       the list of CAPIHook instances, check if pszCalleeModName
   //       is the name of the loaded module to hook its export table and 
   //       re-hook the import tables of all loaded modules.
  
   // Save information about this hooked function
   m_pszCalleeModName   = pszCalleeModName;
   m_pszFuncName        = pszFuncName;
   m_pfnHook            = pfnHook;
   m_pfnOrig            = 
      GetProcAddress(GetModuleHandleA(pszCalleeModName), m_pszFuncName);

   // If function does not exit,... bye bye
   // This happens when the module is not already loaded
   if (m_pfnOrig == NULL)
   {
      wchar_t szPathname[MAX_PATH];
      GetModuleFileNameW(NULL, szPathname, _countof(szPathname));
      wchar_t sz[1024];
      StringCchPrintfW(sz, _countof(sz), 
         TEXT("[%4u - %s] impossible to find %S\r\n"), 
         GetCurrentProcessId(), szPathname, pszFuncName);
      OutputDebugString(sz);
      return;
   }
   

   // Hook this function in all currently loaded modules
   if (!Mhook_SetHook((PVOID*)&m_pfnOrig, m_pfnHook))
     throw std::exception("Mhook_SetHook failed!");
}


///////////////////////////////////////////////////////////////////////////////


CAPIHook::~CAPIHook() {
  Mhook_Unhook((PVOID*)&m_pfnOrig);
}
