//
// OpenCover - S Wilde
//
// This source code is released under the MIT License; see the accompanying license file.
//
#pragma once

#define SEQ_BUFFER_SIZE 8000
#define BRANCH_BUFFER_SIZE 4000
#define VP_BUFFER_SIZE 16000

#pragma pack(push)
#pragma pack(1)

typedef struct SequencePoint
{
    ULONG UniqueId;
    long Offset;
};

typedef struct BranchPoint
{
    ULONG UniqueId;
    long Offset;
    long Path; // for a branch 0 == false, 1 == true ; for a switch it is ...
};

typedef struct VisitPoint
{
    ULONG UniqueId;
};

#pragma pack(pop)

enum MSG_StreamToken : ULONG
{
    MSG_TokenFunctionEnter    = ULONG_MAX,
    MSG_TokenFunctionLeave    = ULONG_MAX - 1,
    MSG_TokenFunctionTailCall = ULONG_MAX - 2,
};

enum MSG_Type : int
{
    MSG_Unknown = 0,
    MSG_TrackAssembly = 1,
    MSG_GetSequencePoints = 2,
    MSG_GetBranchPoints = 3,
    MSG_TrackFunctionElt = 4,
};

#pragma pack(push)
#pragma pack(1)

typedef struct _MSG_TrackAssembly_Request
{
    MSG_Type type;
    WCHAR szModulePath[512];
    WCHAR szAssemblyName[512];
} MSG_TrackAssembly_Request;

typedef struct _MSG_TrackAssembly_Response
{
    BOOL bResponse;
} MSG_TrackAssembly_Response;

typedef struct _MSG_TrackFunctionElt_Request
{
    MSG_Type type;
    int functionToken;
    WCHAR szModulePath[512];
    WCHAR szAssemblyName[512];
} MSG_TrackFunctionElt_Request;

typedef struct _MSG_TrackFunctionElt_Response
{
    BOOL bResponse;
} MSG_TrackFunctionElt_Response;

typedef struct _MSG_GetSequencePoints_Request
{
    MSG_Type type;
    int functionToken;
    WCHAR szModulePath[512];
    WCHAR szAssemblyName[512];
} MSG_GetSequencePoints_Request;

typedef struct _MSG_GetSequencePoints_Response
{
    BOOL hasMore;
    int count;
    SequencePoint points[SEQ_BUFFER_SIZE];
} MSG_GetSequencePoints_Response;

typedef struct _MSG_GetBranchPoints_Request
{
    MSG_Type type;
    int functionToken;
    WCHAR szModulePath[512];
    WCHAR szAssemblyName[512];
} MSG_GetBranchPoints_Request;

typedef struct _MSG_GetBranchPoints_Response
{
    BOOL hasMore;
    int count;
    BranchPoint points[BRANCH_BUFFER_SIZE];
} MSG_GetBranchPoints_Response;

typedef struct _MSG_SendVisitPoints_Request
{
    int count;
    VisitPoint points[VP_BUFFER_SIZE];
} MSG_SendVisitPoints_Request;

#pragma pack(pop)

typedef union _MSG_Union
{
    MSG_Type type;
    MSG_TrackAssembly_Request trackRequest;
    MSG_TrackAssembly_Response trackResponse;
    MSG_TrackFunctionElt_Request trackFunctionEltRequest;
    MSG_TrackFunctionElt_Response trackFunctionEltResponse;
    MSG_GetSequencePoints_Request getSequencePointsRequest;
    MSG_GetSequencePoints_Response getSequencePointsResponse;
    MSG_GetBranchPoints_Request getBranchPointsRequest;
    MSG_GetBranchPoints_Response getBranchPointsResponse;
} MSG_Union;
