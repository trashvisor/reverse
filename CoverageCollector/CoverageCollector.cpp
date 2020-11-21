#include "pin.H"
#include <fstream>
#include <iostream>

KNOB<std::string> TargetModule(KNOB_MODE_WRITEONCE, "pintool",
    "m", "null", "Target module to trace");

bool UseSpecificModule = false;
ADDRINT StartAddress = 0;
ADDRINT EndAddress = 0;

auto pTraceFile = new std::ofstream("Y:\\ReversingVlc\\trace.txt",
    std::ios::out | std::ios::binary);

auto pLogFile = new std::ofstream("Y:\\ReversingVlc\\module_log.txt",
    std::ios::out);

std::vector<std::pair<uintptr_t, uintptr_t>> ModuleRanges;
std::map<uintptr_t, std::string> ModuleNames;

PIN_LOCK Lock;

VOID
InsAnalysisRoutine(ADDRINT InsAddress)
{
    PIN_GetLock(&Lock, 0);

    if (UseSpecificModule)
    {
        if (InsAddress > EndAddress || InsAddress < StartAddress)
        {
            PIN_ReleaseLock(&Lock);
            return;
        }
    }

    // Search for module range
    auto it = std::lower_bound(ModuleRanges.begin(), ModuleRanges.end(), InsAddress,
        [](const std::pair<uintptr_t, uintptr_t>& ValA, const uintptr_t ValB)
        {
            return ValA.first < ValB;
        });
    
    if (it == ModuleRanges.end() || it == ModuleRanges.begin())
    {
        PIN_ReleaseLock(&Lock);
        return;
    }

    it--;

    if (!(InsAddress >= it->first && InsAddress <= it->second))
    {
        PIN_ReleaseLock(&Lock);
        return;
    }

    const auto& Range = *it;
    const auto& ModName = ModuleNames[Range.first];

    *pTraceFile << ModName << "+" << InsAddress - Range.first << '\n';
    
    // I know this is pretty bad for performance
    // But I am not sure how to gracefully terminate a program such that the PIN finish callback is invoked
    // pTraceFile->flush();

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

    auto It = std::lower_bound(ModuleRanges.begin(), ModuleRanges.end(), IMG_StartAddress(Img),
        [] (const std::pair<uintptr_t, uintptr_t>& ValA, const uintptr_t ValB)
        {
            return ValA.first < ValB;
        });

    ModuleRanges.insert(It, std::pair<uintptr_t, uintptr_t>(IMG_StartAddress(Img), IMG_HighAddress(Img)));
    ModuleNames[IMG_StartAddress(Img)] = RelativePath;

    *pLogFile << "Module: " << RelativePath << " Start: 0x" << IMG_StartAddress(Img) << " End: 0x" << IMG_EntryAddress(Img) << std::endl;
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
    // Set the trace to std::hex
    *pLogFile << std::hex;
    *pTraceFile << std::hex;

    if (TargetModule.Value() != "null")
        UseSpecificModule = true;

    INS_AddInstrumentFunction(InsInstrumentFunction, nullptr);
    IMG_AddInstrumentFunction(ImgInstrumentFunction, nullptr);

    PIN_AddFiniFunction(FiniCallback, nullptr);

    PIN_StartProgram();
}