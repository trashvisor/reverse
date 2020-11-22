#include "pin.H"
#include <fstream>
#include <iostream>

KNOB<std::string> TargetModule(KNOB_MODE_WRITEONCE, "pintool",
    "m", "null", "Target module to trace");

ADDRINT StartAddress = ~0ULL;
ADDRINT EndAddress = 0;

auto pTraceFile = new std::ofstream("Y:\\ReversingVlc\\trace.txt",
    std::ios::out | std::ios::binary);

auto pLogFile = new std::ofstream("Y:\\ReversingVlc\\module_log.txt",
    std::ios::out);

PIN_LOCK Lock;

VOID
InsAnalysisRoutine(ADDRINT InsAddress)
{
    PIN_GetLock(&Lock, 0);

    *pTraceFile << TargetModule.Value() << "+" << InsAddress - StartAddress << '\n';

    PIN_ReleaseLock(&Lock);
}

VOID
InsInstrumentFunction(INS Ins, VOID* V)
{
    INS_InsertCall(Ins, IPOINT_BEFORE,
        reinterpret_cast<AFUNPTR>(InsAnalysisRoutine),
        IARG_INST_PTR,
        IARG_END);
}

VOID
ImgInstrumentFunction(IMG Img, VOID* V)
{
    const auto ImgName = IMG_Name(Img);

    // Strip and get relative path name
    const auto RelativePathOffset = ImgName.find_last_of("/\\");
    const auto RelativePath = ImgName.substr(RelativePathOffset + 1);

    // If we find the module specified in the target knob
    // Adjust Start and End so that the tool only traces within that module
    if (RelativePath == TargetModule.Value())
    {
        StartAddress = IMG_StartAddress(Img);
        EndAddress = IMG_HighAddress(Img);
    }

    *pLogFile << "Module: " << RelativePath << " Start: 0x" << IMG_StartAddress(Img) << " End: 0x" << IMG_EntryAddress(Img) << std::endl;
}

VOID
FiniCallback(INT32 Code, VOID* V)
{
    pTraceFile->flush();
}

VOID
TraceInstrumentFunction(TRACE Trace, VOID* V)
{
    for (auto BB = TRACE_BblHead(Trace); BBL_Valid(BB); BB = BBL_Next(BB))
    {
        const auto BBAddress = BBL_Address(BB);

        if (BBAddress > EndAddress || BBAddress < StartAddress)
            continue;

        for (auto Ins = BBL_InsHead(BB); INS_Valid(Ins); Ins = INS_Next(Ins))
        {
            INS_InsertCall(Ins, IPOINT_BEFORE,
                reinterpret_cast<AFUNPTR>(InsAnalysisRoutine),
                IARG_INST_PTR,
                IARG_END);
        }
    }
}

INT32
main(INT32 Argc, CHAR** Argv)
{
    PIN_InitLock(&Lock);

    if (!PIN_Init(Argc, Argv))
        std::cout << "Pin could not start?" << std::endl;

    // Set the module log to std::hex
    // Set the trace to std::hex
    *pLogFile << std::hex;
    *pTraceFile << std::hex;

    TRACE_AddInstrumentFunction(TraceInstrumentFunction, nullptr);
    IMG_AddInstrumentFunction(ImgInstrumentFunction, nullptr);

    PIN_AddFiniFunction(FiniCallback, nullptr);

    PIN_StartProgram();
}
