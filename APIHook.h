/******************************************************************************
Module:  APIHook.h
Notices: Copyright (c) 2008 Jeffrey Richter & Christophe Nasarre
******************************************************************************/


#pragma once


///////////////////////////////////////////////////////////////////////////////


class CAPIHook {
public:
   // Hook a function in all modules
   CAPIHook(PSTR pszCalleeModName, PSTR pszFuncName, PROC pfnHook);

   // Unhook a function from all modules
   ~CAPIHook();

   // Returns the original address of the hooked function
   operator PROC() { return(m_pfnOrig); }

   // Hook module w/CAPIHook implementation?
   // I have to make it static because I need to use it 
   // in ReplaceIATEntryInAllMods
   static BOOL ExcludeAPIHookMod; 



private:
   PCSTR m_pszCalleeModName;     // Module containing the function (ANSI)
   PCSTR m_pszFuncName;          // Function name in callee (ANSI)
   PROC  m_pfnOrig;              // Original function address in callee
   PROC  m_pfnHook;              // Hook function address
};


//////////////////////////////// End of File //////////////////////////////////
