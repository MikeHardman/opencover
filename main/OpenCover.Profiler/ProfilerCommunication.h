//
// OpenCover - S Wilde
//
// This source code is released under the MIT License; see the accompanying license file.
//
#pragma once

#include "Synchronization.h"
#include "SharedMemory.h"
#include "Messages.h"

#include <ppl.h>
#include <concurrent_queue.h>

/// <summary>Handles communication back to the profiler host</summary>
/// <remarks>Currently this is handled by using the WebServices API</remarks>
class ProfilerCommunication
{
private:

public:
    ProfilerCommunication();
    ~ProfilerCommunication(void);
    void Initialise(TCHAR* key);
    void Stop();

public:
    bool TrackAssembly(WCHAR* pModulePath, WCHAR* pAssemblyName);
	bool TrackFunctionElt(WCHAR* pModulePath, WCHAR* pAssemblyName, FunctionID functionId);
    bool GetPoints(mdToken functionToken, WCHAR* pModulePath, WCHAR* pAssemblyName, std::vector<SequencePoint> &seqPoints, std::vector<BranchPoint> &brPoints);
    inline void AddVisitPoint(ULONG uniqueId) { if (uniqueId!=0) m_queue.push(uniqueId); }
    inline void AddEltMessage(ULONG messageMarker, int functionID) { m_queue.push(messageMarker); m_queue.push(functionID); }

private:
    void SendVisitPoints();
    bool GetSequencePoints(mdToken functionToken, WCHAR* pModulePath, WCHAR* pAssemblyName, std::vector<SequencePoint> &points);
    bool GetBranchPoints(mdToken functionToken, WCHAR* pModulePath, WCHAR* pAssemblyName, std::vector<BranchPoint> &points);
	void SendFunctionElt(ULONG eltTypeMarker, ULONG functionId);

private:
    tstring m_key;

    template<class BR, class PR>
    void RequestInformation(BR buildRequest, PR processResults);

private:
    CMutex m_mutexCommunication;
    CSharedMemory m_memoryCommunication;
    CEvent m_eventProfilerRequestsInformation;
    CEvent m_eventInformationReadyForProfiler;
    MSG_Union *m_pMSG;
    CEvent m_eventInformationReadByProfiler;

private:
    CMutex m_mutexResults;
    CSharedMemory m_memoryResults;
    CEvent m_eventProfilerHasResults;
    CEvent m_eventResultsHaveBeenReceived;
    MSG_SendVisitPoints_Request *m_pVisitPoints;
    Concurrency::concurrent_queue<ULONG> m_queue;
    Concurrency::task_group m_tasks;
};

