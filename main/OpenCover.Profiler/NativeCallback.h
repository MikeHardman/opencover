// This source code is released under the MIT License; see the accompanying license file.

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

void _FunctionEnter2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func, 
    COR_PRF_FUNCTION_ARGUMENT_INFO *argumentInfo);

void _FunctionLeave2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func, 
    COR_PRF_FUNCTION_ARGUMENT_RANGE *retvalRange);

void _FunctionTailcall2(
    FunctionID funcID, 
    UINT_PTR clientData, 
    COR_PRF_FRAME_INFO func);

#ifdef __cplusplus
}
#endif

// Implement these elsewhere, once, as global handlers for the ELT hooks

// http://msdn.microsoft.com/en-us/library/aa964981.aspx
void __stdcall FunctionEnter2Global(
    /*[in]*/FunctionID                          funcID, 
    /*[in]*/UINT_PTR                            clientData, 
    /*[in]*/COR_PRF_FRAME_INFO                  func, 
    /*[in]*/COR_PRF_FUNCTION_ARGUMENT_INFO      *argumentInfo);

// http://msdn.microsoft.com/en-us/library/aa964942.aspx
void __stdcall FunctionLeave2Global(
    /*[in]*/FunctionID                          funcID, 
    /*[in]*/UINT_PTR                            clientData, 
    /*[in]*/COR_PRF_FRAME_INFO                  func, 
    /*[in]*/COR_PRF_FUNCTION_ARGUMENT_RANGE     *retvalRange);

// http://msdn.microsoft.com/en-us/library/aa964754.aspx
void __stdcall FunctionTailcall2Global(
    /*[in]*/FunctionID                          funcID, 
    /*[in]*/UINT_PTR                            clientData, 
    /*[in]*/COR_PRF_FRAME_INFO                  func);

// See: http://en.wikipedia.org/wiki/X86_calling_conventions
//
// These macros provide assembly epilogue/prologue for fulfilling the caller's obligations before calling a a stdcall 
// or cdecl function. This means saving the EAX, ECX and EDX registers.
//
// Additionally, during a leave hook we need to preserve return value about to be returned by the hooked function. 
// This is EAX and ST0 (FP register).

// These bits are the top of the floating point register "stack". If unset the FP stack is empty and should not be 
// saved/restored.
#define X86_ASM_FPSTATUS_TOP 3800h

// Reserve space for local state on the stack. Store EAX, ECX and EDX.
#define X86_ASM_ELT_HOOK_PROLOGUE \
	__asm { sub esp, __LOCAL_SIZE } \
	__asm { push eax } \
	__asm { push ecx } \
	__asm { push edx }

// 1. Create space on the stack for the FP register value, even if we're not storing it
// 2. Get the FPU status word
// 3. Check whether there's any register in use (i.e. does ST0 have a value)
// 4. Push the status flags to indicate whether there is
// 6. If there isn't skip the store
// 7. Store the FP register int the double-word space created earlier
#define X86_ASM_ELT_LEAVE_HOOK_SAVE \
	__asm { sub     esp, 8 } \
	__asm { fstsw   ax } \
	__asm { test    ax, X86_ASM_FPSTATUS_TOP } \
	__asm { pushfd } \
	__asm { jz      EltHookDontPushFPReg } \
	__asm { fstp    qword ptr [esp+4] } \
EltHookDontPushFPReg:

// 1. Pop the status flags indicating whether the FP register was stored
// 2. Don't restore the register if it wasn't stored
// 3. Restore the FP register
// 4. Skip the storage location for the FP register
#define X86_ASM_ELT_LEAVE_HOOK_RESTORE \
	__asm { popfd			} \
	__asm { jz      EltHookDontPopFPRef	} \
	__asm { fld     qword ptr [esp]	} \
EltHookDontPopFPRef: \
	__asm { add    esp, 8				} \

// Restore EDX, ECX and EAX in that order. Remove local state from the stack.
#define X86_ASM_ELT_HOOK_EPILOGUE(ARGS_SIZE) \
	__asm { pop edx } \
	__asm { pop ecx } \
	__asm { pop eax } \
	__asm { add esp, __LOCAL_SIZE } \
	__asm { ret ARGS_SIZE }
