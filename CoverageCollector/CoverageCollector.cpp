#include "pin.H"
#include <fstream>
#include <iostream>

KNOB<std::string> TargetModule(KNOB_MODE_WRITEONCE, "pintool",
    "m", "null", "Target module to trace");

// Default start and end address such that 
// the condition InsAddress < StartAddress || InsAddress > EndAddress
// always returns false unless a module is specified
ADDRINT StartAddress = 0;
ADDRINT EndAddress = ~0;

auto pTraceFile = new std::ofstream("trace.txt",
    std::ios::out | std::ios::binary);

auto pLogFile = new std::ofstream("module_log.txt",
    std::ios::out);

PIN_LOCK Lock;

VOID
InsAnalysisRoutine(ADDRINT InsAddress)
{
    PIN_GetLock(&Lock, 0);

    if (InsAddress < StartAddress || InsAddress > EndAddress)
        return;

    *pTraceFile << InsAddress << '\n';
    
    // I know this is pretty bad for performance
    // But I am not sure how to gracefully terminate a program such that the PIN finish callback is invoked
    pTraceFile->flush();

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
    const auto RelativePath = ImgName.substr(RelativePathOffset);

    const auto Start = IMG_StartAddress(Img);
    const auto End = IMG_HighAddress(Img);

    // If we find the module specified in the target knob
    // Adjust Start and End so that the tool only traces within that module
    if (RelativePath == TargetModule.Value())
    {
        StartAddress = IMG_StartAddress(Img);
        EndAddress = IMG_HighAddress(Img);
    }

    *pLogFile << RelativePath << "0x" << Start << ":0x" << End << std::endl;
}

VOID
FiniCallback(INT32 Code, VOID* V)
{
    pTraceFile->flush();
}

INT32
main(INT32 Argc, CHAR **Argv)
{
    PIN_InitLock(&Lock);

    if (!PIN_Init(Argc, Argv))
        std::cout << "Pin could not start?" << std::endl;

    // Set the module log to std::hex
    *pLogFile << std::hex;

    INS_AddInstrumentFunction(InsInstrumentFunction, nullptr);
    IMG_AddInstrumentFunction(ImgInstrumentFunction, nullptr);
    PIN_AddFiniFunction(FiniCallback, nullptr);

    PIN_StartProgram();
}