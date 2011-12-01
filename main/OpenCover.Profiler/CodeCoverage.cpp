//
// OpenCover - S Wilde
//
// This source code is released under the MIT License; see the accompanying license file.
//
// CodeCoverage.cpp : Implementation of CCodeCoverage

#include "stdafx.h"
#include "CodeCoverage.h"
#include "NativeCallback.h"
#include "CoverageInstrumentation.h"
#include "dllmain.h"

//
// Global hooks to profiler callbacks
//

// http://msdn.microsoft.com/en-us/library/aa964981.aspx
void __stdcall FunctionEnter2Global(
    /*[in]*/FunctionID                          funcID, 
    /*[in]*/UINT_PTR                            clientData, 
    /*[in]*/COR_PRF_FRAME_INFO                  func, 
    /*[in]*/COR_PRF_FUNCTION_ARGUMENT_INFO      *argumentInfo)
{
	CCodeCoverage::g_pProfiler->FunctionEnter(funcID, clientData, func, argumentInfo);
}

// http://msdn.microsoft.com/en-us/library/aa964942.aspx
void __stdcall FunctionLeave2Global(
    /*[in]*/FunctionID                          funcID, 
    /*[in]*/UINT_PTR                            clientData, 
    /*[in]*/COR_PRF_FRAME_INFO                  func, 
    /*[in]*/COR_PRF_FUNCTION_ARGUMENT_RANGE     *retvalRange)
{
	CCodeCoverage::g_pProfiler->FunctionLeave(funcID, clientData, func, retvalRange);
}

// http://msdn.microsoft.com/en-us/library/aa964754.aspx
void __stdcall FunctionTailcall2Global(
    /*[in]*/FunctionID                          funcID, 
    /*[in]*/UINT_PTR                            clientData, 
    /*[in]*/COR_PRF_FRAME_INFO                  func)
{
	CCodeCoverage::g_pProfiler->FunctionTailCall(funcID, clientData, func);
}

// http://msdn.microsoft.com/en-us/library/aa964957.aspx
UINT_PTR __stdcall FunctionIDMapperGlobal(FunctionID funcID, BOOL *pbHookFunction)
{
	return CCodeCoverage::g_pProfiler->FunctionIDMapper(funcID, pbHookFunction);
}


CCodeCoverage* CCodeCoverage::g_pProfiler = NULL;
// CCodeCoverage

/// <summary>Handle <c>ICorProfilerCallback::Initialize</c></summary>
/// <remarks>Initialize the profiling environment and establish connection to the host</remarks>
HRESULT STDMETHODCALLTYPE CCodeCoverage::Initialize( 
    /* [in] */ IUnknown *pICorProfilerInfoUnk) 
{
    ATLTRACE(_T("::Initialize"));
    
    m_isV4 = FALSE;
    OLECHAR szGuid[40]={0};
    int nCount = ::StringFromGUID2(CLSID_CodeCoverage, szGuid, 40);
    ::OutputDebugStringW(szGuid);

    WCHAR szModuleName[MAX_PATH];
    GetModuleFileNameW(_AtlModule.m_hModule, szModuleName, MAX_PATH);
    ::OutputDebugStringW(szModuleName);

    if (g_pProfiler!=NULL) ATLTRACE(_T("Another instance of the profiler is running under this process..."));

    m_profilerInfo = pICorProfilerInfoUnk;
    if (m_profilerInfo != NULL) ATLTRACE(_T("    ::Initialize (m_profilerInfo OK)"));
    if (m_profilerInfo == NULL) return E_FAIL;
    m_profilerInfo2 = pICorProfilerInfoUnk;
    if (m_profilerInfo2 != NULL) ATLTRACE(_T("    ::Initialize (m_profilerInfo2 OK)"));
    if (m_profilerInfo2 == NULL) return E_FAIL;
    m_profilerInfo3 = pICorProfilerInfoUnk;
    if (m_profilerInfo3 != NULL) 
    {
        m_isV4 = TRUE;
        ATLTRACE(_T("    ::Initialize (m_profilerInfo3 OK)"));
    }

    TCHAR key[1024];
    ::GetEnvironmentVariable(_T("OpenCover_Profiler_Key"), key, 1024);
    ATLTRACE(_T("key = %s"), key);
    m_host.Initialise(key);

    DWORD dwMask = 0;
    dwMask |= COR_PRF_MONITOR_MODULE_LOADS;			// Controls the ModuleLoad, ModuleUnload, and ModuleAttachedToAssembly callbacks.
    dwMask |= COR_PRF_MONITOR_JIT_COMPILATION;	    // Controls the JITCompilation, JITFunctionPitched, and JITInlining callbacks.
    dwMask |= COR_PRF_DISABLE_INLINING;				// Disables all inlining.
    dwMask |= COR_PRF_DISABLE_OPTIMIZATIONS;		// Disables all code optimizations.
	dwMask |= COR_PRF_MONITOR_ENTERLEAVE;           // Profile function enter/leave/tailcall
	if (m_isV4) dwMask |= COR_PRF_DISABLE_TRANSPARENCY_CHECKS_UNDER_FULL_TRUST; 

    m_profilerInfo2->SetEventMask(dwMask);

    g_pProfiler = this;

    return S_OK; 
}

/// <summary>Handle <c>ICorProfilerCallback::Shutdown</c></summary>
HRESULT STDMETHODCALLTYPE CCodeCoverage::Shutdown( void) 
{ 
    ATLTRACE(_T("::Shutdown"));
    m_host.Stop();
    g_pProfiler = NULL;
    return S_OK; 
}

/// <summary>Handle <c>ICorProfilerCallback::ModuleAttachedToAssembly</c></summary>
/// <remarks>Inform the host that we have a new module attached and that it may be 
/// of interest</remarks>
HRESULT STDMETHODCALLTYPE CCodeCoverage::ModuleAttachedToAssembly( 
    /* [in] */ ModuleID moduleId,
    /* [in] */ AssemblyID assemblyId)
{
    std::wstring modulePath = GetModulePath(moduleId);
    std::wstring assemblyName = GetAssemblyName(assemblyId);
    ATLTRACE(_T("::ModuleAttachedToAssembly(%X => %s, %X => %s)"), 
        moduleId, W2CT(modulePath.c_str()), 
        assemblyId, W2CT(assemblyName.c_str()));
    m_allowModules[modulePath] = m_host.TrackAssembly((LPWSTR)modulePath.c_str(), (LPWSTR)assemblyName.c_str());
    m_allowModulesAssemblyMap[modulePath] = assemblyName;
    return S_OK; 
}

/// <summary>An unmanaged callback that can be called from .NET that has a single I4 parameter</summary>
/// <remarks>
/// void (__fastcall *pt)(long) = &SequencePointVisit ;
/// mdSignature pmsig = GetUnmanagedMethodSignatureToken_I4(moduleId);
/// </remarks>
static void __fastcall InstrumentPointVisit(ULONG seq)
{
    CCodeCoverage::g_pProfiler->m_host.AddVisitPoint(seq);
}

/// <summary>Handle <c>ICorProfilerCallback::JITCompilationStarted</c></summary>
/// <remarks>The 'workhorse' </remarks>
HRESULT STDMETHODCALLTYPE CCodeCoverage::JITCompilationStarted( 
        /* [in] */ FunctionID functionId,
        /* [in] */ BOOL fIsSafeToBlock)
{
    std::wstring moduleName;
    mdToken functionToken;
    ModuleID moduleId;

    if (GetTokenAndModule(functionId, functionToken, moduleId, moduleName))
    {
        if (!m_allowModules[moduleName]) return S_OK;

        std::pair<std::wstring, ULONG32> key(moduleName, functionToken);
        if (m_jitdMethods[key]) return S_OK;
        m_jitdMethods[key] = true;

        ATLTRACE(_T("::JITCompilationStarted(%X, %d, (%X)%s)"), functionId, functionToken, moduleId, W2CT(moduleName.c_str()));
        
        std::vector<SequencePoint> seqPoints;
        std::vector<BranchPoint> brPoints;

        if (m_host.GetPoints(functionToken, (LPWSTR)moduleName.c_str(), 
            (LPWSTR)m_allowModulesAssemblyMap[moduleName].c_str(), seqPoints, brPoints))
        {
            if (seqPoints.size()==0) return S_OK;
            LPCBYTE pMethodHeader = NULL;
            ULONG iMethodSize = 0;
            m_profilerInfo2->GetILFunctionBody(moduleId, functionToken, &pMethodHeader, &iMethodSize);

            IMAGE_COR_ILMETHOD* pMethod = (IMAGE_COR_ILMETHOD*)pMethodHeader;
            
            void (__fastcall *spt)(ULONG) = &InstrumentPointVisit ;
            mdSignature spvsig = GetUnmanagedMethodSignatureToken_I4(moduleId);

            CoverageInstrumentation instumentedMethod(pMethod);
            instumentedMethod.IncrementStackSize(2);

            ATLTRACE(_T("Instrumenting..."));
            //seqPoints.clear();
            //brPoints.clear();

            instumentedMethod.AddSequenceCoverage(spvsig, (FPTR)spt, seqPoints);
            instumentedMethod.AddBranchCoverage(spvsig, (FPTR)spt, brPoints);

            instumentedMethod.DumpIL();

            CComPtr<IMethodMalloc> methodMalloc;
            m_profilerInfo2->GetILFunctionBodyAllocator(moduleId, &methodMalloc);
            IMAGE_COR_ILMETHOD* pNewMethod = (IMAGE_COR_ILMETHOD*)methodMalloc->Alloc(instumentedMethod.GetMethodSize());
            instumentedMethod.WriteMethod(pNewMethod);
            m_profilerInfo2->SetILFunctionBody(moduleId, functionToken, (LPCBYTE) pNewMethod);

            ULONG mapSize = instumentedMethod.GetILMapSize();
            COR_IL_MAP * pMap = (COR_IL_MAP *)CoTaskMemAlloc(mapSize * sizeof(COR_IL_MAP));
            instumentedMethod.PopulateILMap(mapSize, pMap);
            m_profilerInfo2->SetILInstrumentedCodeMap(functionId, TRUE, mapSize, pMap);

            // only do this for .NET4 as there are issues with earlier runtimes (Access Violations)
            if (m_isV4) CoTaskMemFree(pMap);
        }
    }
    
    return S_OK; 
}

// Callback where the profiler requests function ID mapping (not used here) and whether to attach ELT hooks for a 
// function. We ask the host whether to add ELT hooks.
UINT_PTR CCodeCoverage::FunctionIDMapper(
                FunctionID functionId,
                BOOL *pbHookFunction)
{
    std::wstring moduleName;
    mdToken functionToken;
    ModuleID moduleId;

    if (GetTokenAndModule(functionId, functionToken, moduleId, moduleName))
    {
		*pbHookFunction = m_host.TrackFunctionElt(
			(LPWSTR)moduleName.c_str(), (LPWSTR)m_allowModulesAssemblyMap[moduleName].c_str(), functionToken);
	}
	return functionId;
}

// Callback for function enter ELT hook. Adds an ELT message to the host stream.
void STDMETHODCALLTYPE CCodeCoverage::FunctionEnter(FunctionID id, UINT_PTR clientData, COR_PRF_FRAME_INFO frame, COR_PRF_FUNCTION_ARGUMENT_INFO *argumentInfo)
{
	m_host.AddEltMessage(MSG_TokenFunctionEnter, id);
}

// Callback for function leave ELT hook. Adds an ELT message to the host stream.
void STDMETHODCALLTYPE CCodeCoverage::FunctionLeave(FunctionID id, UINT_PTR clientData, COR_PRF_FRAME_INFO frame, COR_PRF_FUNCTION_ARGUMENT_RANGE* retvalRange)
{
	m_host.AddEltMessage(MSG_TokenFunctionLeave, id);
}

// Callback for function tail call ELT hook. Adds an ELT message to the host stream.
void STDMETHODCALLTYPE CCodeCoverage::FunctionTailCall(FunctionID id, UINT_PTR clientData, COR_PRF_FRAME_INFO frame)
{
	m_host.AddEltMessage(MSG_TokenFunctionTailCall, id);
}
