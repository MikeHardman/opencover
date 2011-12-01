#include "StdAfx.h"
#include "NativeCallback.h"
#include "CodeCoverage.h"

#if defined(_WIN64)
void _FunctionEnter2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func, 
    COR_PRF_FUNCTION_ARGUMENT_INFO *argumentInfo)
{
    FunctionEnter2Global(funcID, clientData, func, argumentInfo);
}

void _FunctionLeave2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func, 
    COR_PRF_FUNCTION_ARGUMENT_RANGE *retvalRange)
{
    FunctionLeave2Global(funcID, clientData, func, retvalRange);
}

void _FunctionTailcall2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func)
{
    FunctionTailcall2Global(funcID, clientData, func);
}
#else
void _declspec(naked) _FunctionEnter2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func, 
    COR_PRF_FUNCTION_ARGUMENT_INFO *argumentInfo)
{
	X86_ASM_ELT_HOOK_PROLOGUE;

	FunctionEnter2Global(funcID, clientData, func, argumentInfo);

	X86_ASM_ELT_HOOK_EPILOGUE(SIZE funcID + SIZE clientData + SIZE func + SIZE argumentInfo);
}

void _declspec(naked) _FunctionLeave2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func, 
    COR_PRF_FUNCTION_ARGUMENT_RANGE *retvalRange)
{
	X86_ASM_ELT_HOOK_PROLOGUE;
	X86_ASM_ELT_LEAVE_HOOK_SAVE;

	FunctionLeave2Global(funcID, clientData, func, retvalRange);
	
	X86_ASM_ELT_LEAVE_HOOK_RESTORE;
	X86_ASM_ELT_HOOK_EPILOGUE(SIZE funcID + SIZE clientData + SIZE func + SIZE retvalRange);
}

void _declspec(naked) _FunctionTailcall2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func)
{
	X86_ASM_ELT_HOOK_PROLOGUE;

	FunctionTailcall2Global(funcID, clientData, func);

	X86_ASM_ELT_HOOK_EPILOGUE(SIZE funcID + SIZE clientData + SIZE func);
}
#endif
