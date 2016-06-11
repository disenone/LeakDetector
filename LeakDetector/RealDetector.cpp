#include "RealDetector.h"
#include "utils.h"
#include <cassert>
#include <DbgHelp.h>
#include <iostream>
#include <atlconv.h>

using namespace std;
using namespace LDTools;

// Relative Virtual Address to Virtual Address conversion.
#define R2VA(modulebase, rva)  (((PBYTE)modulebase) + rva)


bool RealDetector::m_trace = true;
string RealDetector::m_moduleName;
std::map<void*, HeapContex> RealDetector::m_heapTrace;
RealDetector leakd;

void printTrace(const UINT_PTR* pFrame = nullptr, size_t frameSize = 0);

// ��ʼ����ڴ�й¶������ malloc �� free ����
bool RealDetector::start(const char* moduleName)
{
	logMessage("============== LeakDetector::start ===============\n");

	HMODULE module;
	if (moduleName)
	{
		module = GetModuleHandleA(moduleName);
	}
	else
		module = GetModuleHandleA(NULL);

	if (!patchImport(module, "ucrtbased.dll", NULL, "malloc", _malloc))
		return false;
	if (!patchImport(module, "ucrtbased.dll", NULL, "_free_dbg", _crt_free_dbg))
		return false;

	m_moduleName = string(moduleName);

	SymInitialize(GetCurrentProcess(), NULL, TRUE);
	return true;
}

// ֹͣ��⣬��ԭ malloc �� free ����������ӡ�ڴ�й¶���
bool RealDetector::stop()
{
	HMODULE module = GetModuleHandleA(m_moduleName.c_str());

	unpatchImport(module, "ucrtbased.dll", NULL, "malloc", _malloc);
	unpatchImport(module, "ucrtbased.dll", NULL, "_free_dbg", _crt_free_dbg);

	logMessage("============== LeakDetector::stop ================\n");
	bool ret = true;
	if (m_heapTrace.size() > 0)
	{
		ret = false;
		logMessage("Memory Leak Detected: total %d\n", m_heapTrace.size());

		int i = 1;
		for (const auto heap : m_heapTrace)
		{
			logMessage("\nNum %d:\n", i);
			printTrace(heap.second.frames.data(), heap.second.frames.size());
			++i;
		}
		logMessage("\n");
	}
	else
	{
		logMessage("No Memory Leak Detected.\n");
	}

	SymCleanup(GetCurrentProcess());
	m_heapTrace.clear();
	return ret;
}

bool RealDetector::check()
{
	return m_heapTrace.empty();
}

void* RealDetector::_malloc(size_t size)
{
	static void* pcrtd_malloc = nullptr;
	if (pcrtd_malloc == nullptr)
	{
		HMODULE ucrtbased = GetModuleHandleA("ucrtbased.dll");
		pcrtd_malloc = GetProcAddress(ucrtbased, "malloc");
	}

	void* ret = ((malloc_t)pcrtd_malloc)(size);
	
	// m_heapTrace ��¼ջ�ṹҲ�ᵼ�·���ѿռ䣬�����ڼ�¼֮ǰ���Ƚ�ֹ��⣬�����ݹ�ѭ������
	if (!m_trace)
	{
		return ret;
	}

	m_trace = false;

	// �õ���ջ
	UINT32 maxframes = 62;
	UINT_PTR myFrames[62];
	ZeroMemory(myFrames, sizeof(UINT_PTR) * maxframes);
	ULONG BackTraceHash;
	maxframes = RtlCaptureStackBackTrace(0, maxframes, 
		reinterpret_cast<PVOID*>(myFrames), &BackTraceHash);
	m_heapTrace.emplace(ret, HeapContex{ ret,{ myFrames, myFrames + maxframes } });

	m_trace = true;

	return ret;
}

void RealDetector::_crt_free_dbg(void* prt, size_t size)
{
	static void* pcrtd_free_dbg = nullptr;
	if (pcrtd_free_dbg == nullptr)
	{
		HMODULE ucrtbased = GetModuleHandle(L"ucrtbased.dll");
		pcrtd_free_dbg = GetProcAddress(ucrtbased, "_free_dbg");
	}

	m_heapTrace.erase(prt);

	return ((free_dbg_t)pcrtd_free_dbg)(prt, size);
}

/* �� importModule �е� IAT (Import Address Table) ��ĳ�������滻�ɱ�ĺ�����
 * importModule ����õ���� module �ĺ������������������Ҫ patch �ĺ�����
 * ����Ҫ���ľ����� import module �ĳɵ��������Զ���ĺ�����
 *
 * - importModule (IN): Ҫ����� module����� module ���õ���� module ����Ҫ patch �ĺ���
 *
 * - exportModuleName (IN): ��Ҫ patch �ĺ������Ե� module ����
 *
 * - exportModulePath (IN): export module ���ڵ�·�������ȳ����� path ������ export module��
 *			���ʧ�ܣ����� name ������
 * - importName (IN): ������
 *
 * - replacement (IN): ����ĺ���ָ��
 *
 * Return Valur: �ɹ� true������ false
*/
bool RealDetector::patchImport(
	HMODULE importModule,
	LPCSTR exportModuleName,
	LPCSTR exportModulePath,
	LPCSTR importName,
	LPCVOID replacement)
{
	HMODULE                  exportmodule;
	IMAGE_THUNK_DATA        *iate;
	IMAGE_IMPORT_DESCRIPTOR *idte;
	FARPROC                  import;
	DWORD                    protect;
	IMAGE_SECTION_HEADER    *section;
	ULONG                    size;

	assert(exportModuleName != NULL);

	idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importModule, 
		TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
	if (idte == NULL) 
	{
		logMessage("patchImport failed: idte == NULL\n");
		return false;
	}
	while (idte->FirstThunk != 0x0) 
	{
		if (strcmp((PCHAR)R2VA(importModule, idte->Name), exportModuleName) == 0) 
		{
			break;
		}
		idte++;
	}
	if (idte->FirstThunk == 0x0) 
	{
		logMessage("patchImport failed: idte->FirstThunk == 0x0\n");
		return false;
	}

	if (exportModulePath != NULL) 
	{
		exportmodule = GetModuleHandleA(exportModulePath);
	}
	else 
	{
		exportmodule = GetModuleHandleA(exportModuleName);
	}
	assert(exportmodule != NULL);
	import = GetProcAddress(exportmodule, importName);
	assert(import != NULL);

	iate = (IMAGE_THUNK_DATA*)R2VA(importModule, idte->FirstThunk);
	while (iate->u1.Function != 0x0) 
	{
		if (iate->u1.Function == (DWORD_PTR)import) 
		{
			VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), 
				PAGE_READWRITE, &protect);
			iate->u1.Function = (DWORD_PTR)replacement;
			VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), 
				protect, &protect);
			return true;
		}
		iate++;
	}

	return false;
}

/* �ָ�������ĺ���
 *
 * - importModule (IN): Ҫ����� module����� module ���õ���� module ����Ҫ patch �ĺ���
 *
 * - exportModuleName (IN): ��Ҫ patch �ĺ������Ե� module ����
 *
 * - exportModulePath (IN): export module ���ڵ�·�������ȳ����� path ������ export module��
 *			���ʧ�ܣ����� name ������
 * - importName (IN): ������
 *
 * - replacement (IN): ����ĺ���ָ��
 *
 * Return Valur: �ɹ� true������ false
*/
bool RealDetector::unpatchImport(
	HMODULE importmodule,
	LPCSTR exportmodulename,
	LPCSTR exportmodulepath,
	LPCSTR importname,
	LPCVOID replacement)
{
	HMODULE                  exportmodule;
	IMAGE_THUNK_DATA        *iate;
	IMAGE_IMPORT_DESCRIPTOR *idte;
	FARPROC                  import;
	DWORD                    protect;
	IMAGE_SECTION_HEADER    *section;
	ULONG                    size;

	assert(exportmodulename != NULL);

	idte = (IMAGE_IMPORT_DESCRIPTOR*)ImageDirectoryEntryToDataEx((PVOID)importmodule, TRUE,
		IMAGE_DIRECTORY_ENTRY_IMPORT, &size, &section);
	if (idte == NULL) {
		return false;
	}
	while (idte->OriginalFirstThunk != 0x0) {
		if (strcmp((PCHAR)R2VA(importmodule, idte->Name), exportmodulename) == 0) {
			break;
		}
		idte++;
	}
	if (idte->OriginalFirstThunk == 0x0) {
		return false;
	}

	if (exportmodulepath != NULL) {
		exportmodule = GetModuleHandleA(exportmodulepath);
	}
	else {
		exportmodule = GetModuleHandleA(exportmodulename);
	}
	assert(exportmodule != NULL);
	import = GetProcAddress(exportmodule, importname);
	assert(import != NULL);

	iate = (IMAGE_THUNK_DATA*)R2VA(importmodule, idte->FirstThunk);
	while (iate->u1.Function != 0x0) {
		if (iate->u1.Function == (DWORD_PTR)replacement) {
			VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), PAGE_READWRITE, &protect);
			iate->u1.Function = (DWORD_PTR)import;
			VirtualProtect(&iate->u1.Function, sizeof(iate->u1.Function), protect, &protect);
			return true;
		}
		iate++;
	}

	return false;
}

// converts "Lasr Error" code into text
static CHAR *getLastErrorText(CHAR *pBuf, ULONG bufSize)
{
	ULONG retSize;
	CHAR* pTemp = NULL;

	if (bufSize < 16) {
		if (bufSize > 0) {
			pBuf[0] = '\0';
		}
		return(pBuf);
	}
	retSize = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_ARGUMENT_ARRAY,
		NULL,
		GetLastError(),
		LANG_NEUTRAL,
		(LPSTR)&pTemp,
		0,
		NULL);
	if (!retSize || pTemp == NULL) {
		pBuf[0] = '\0';
	}
	else {
		pTemp[strlen(pTemp) - 2] = '\0'; //remove cr and newline character
		sprintf_s(pBuf, bufSize, "%0.*s (0x%x)", bufSize - 16, pTemp, GetLastError());
		LocalFree((HLOCAL)pTemp);
	}
	return(pBuf);
}

void printLastError()
{
	char buf[BUF_SIZE];
	getLastErrorText(buf, BUF_SIZE);
	logMessage(buf);
}

LPCSTR getFunctionName(SIZE_T programCounter, DWORD64& displacement64,
	SYMBOL_INFO* functionInfo)
{
	// Initialize structures passed to the symbol handler.
	functionInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);
	functionInfo->MaxNameLen = 256;

	// Try to get the name of the function containing this program
	// counter address.
	displacement64 = 0;
	LPCSTR functionName;
	HANDLE hProcess = GetCurrentProcess();
	if (SymFromAddr(hProcess, programCounter, &displacement64, functionInfo)) {
		functionName = functionInfo->Name;
	}
	else {
		printLastError();
		sprintf_s(functionInfo->Name, (size_t)256, "0x%x", programCounter);
		functionName = functionInfo->Name;
		displacement64 = 0;
	}
	return functionName;
}

HMODULE GetCallingModule(UINT_PTR pCaller)
{
	HMODULE hModule = NULL;
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery((LPCVOID)pCaller, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == sizeof(MEMORY_BASIC_INFORMATION))
	{
		// the allocation base is the beginning of a PE file
		hModule = (HMODULE)mbi.AllocationBase;
	}
	return hModule;
}

DWORD resolveFunction(SIZE_T programCounter, IMAGEHLP_LINE* sourceInfo, DWORD displacement,
	LPCSTR functionName, LPSTR stack_line, DWORD stackLineSize)
{
	char callingModuleName[260];
	HMODULE hCallingModule = GetCallingModule(programCounter);
	LPSTR moduleName = "(Module name unavailable)";
	if (hCallingModule &&
		GetModuleFileNameA(hCallingModule, callingModuleName, _countof(callingModuleName)) > 0)
	{

		moduleName = strrchr(callingModuleName, '\\');
		if (moduleName == NULL)
			moduleName = strrchr(callingModuleName, '/');
		if (moduleName != NULL)
			moduleName++;
		else
			moduleName = callingModuleName;
	}
	ZeroMemory(stack_line, stackLineSize * sizeof(char));
	// Display the current stack frame's information.
	if (sourceInfo)
	{
		if (displacement == 0)
		{
			sprintf_s(stack_line, stackLineSize, "    %s (%d): %s!%s()\n",
				sourceInfo->FileName, sourceInfo->LineNumber, moduleName,
				functionName);
		}
		else
		{
			sprintf_s(stack_line, stackLineSize, "    %s (%d): %s!%s() + 0x%x bytes\n",
				sourceInfo->FileName, sourceInfo->LineNumber, moduleName,
				functionName, displacement);
		}
	}
	else
	{
		if (displacement == 0)
		{
			sprintf_s(stack_line, stackLineSize, "    %s!%s()\n",
				moduleName, functionName);
		}
		else
		{
			sprintf_s(stack_line, stackLineSize, "    %s!%s() + 0x%x bytes\n",
				moduleName, functionName, displacement);
		}
	}

	LPSTR end = find(stack_line, stack_line + stackLineSize, '\0');
	DWORD NumChars = (DWORD)(end - stack_line);
	stack_line[NumChars] = '\0';
	return NumChars;
}

void printTrace(const UINT_PTR* pFrame/* = nullptr*/, size_t frameSize/* = 0*/)
{

	UINT32 maxframes = 62;
	UINT_PTR myFrames[62];
	if (pFrame == 0)
	{
		ZeroMemory(myFrames, sizeof(UINT_PTR) * maxframes);
		ULONG BackTraceHash;
		maxframes = RtlCaptureStackBackTrace(0, maxframes, reinterpret_cast<PVOID*>(myFrames), &BackTraceHash);
		pFrame = myFrames;
		frameSize = maxframes;
	}

	UINT32  startIndex = 0;

	int unresolvedFunctionsCount = 0;
	IMAGEHLP_LINE  sourceInfo = { 0 };
	sourceInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE);

	// Use static here to increase performance, and avoid heap allocs.
	// It's thread safe because of g_heapMapLock lock.
	
	bool isPrevFrameInternal = false;
	DWORD NumChars = 0;

	const size_t max_line_length = 512;
	const int resolvedCapacity = 62 * max_line_length;
	const size_t allocedBytes = resolvedCapacity * sizeof(char);
	char resolved[resolvedCapacity];
	static char stack_line[resolvedCapacity] = "";

	if (resolved) 
	{
		ZeroMemory(resolved, allocedBytes);
	}
	HANDLE hProcess = GetCurrentProcess();
	int resolvedLength = 0;
	// Iterate through each frame in the call stack.
	for (UINT32 frame = 0; frame < frameSize; frame++)
	{
		if (pFrame[frame] == 0)
			break;
		// Try to get the source file and line number associated with
		// this program counter address.
		SIZE_T programCounter = pFrame[frame];

		DWORD64 displacement64;
		BYTE symbolBuffer[sizeof(SYMBOL_INFO) + 256 * sizeof(char)];
		LPCSTR functionName = getFunctionName(programCounter, displacement64, (SYMBOL_INFO*)&symbolBuffer);

		// It turns out that calls to SymGetLineFromAddrW64 may free the very memory we are scrutinizing here
		// in this method. If this is the case, m_Resolved will be null after SymGetLineFromAddrW64 returns.
		// When that happens there is nothing we can do except crash.
		DWORD displacement = 0;

		BOOL foundline = SymGetLineFromAddr(hProcess, programCounter, &displacement, &sourceInfo);

		bool isFrameInternal = false;

		// show one allocation function for context
		if (NumChars > 0 && !isFrameInternal && isPrevFrameInternal) 
		{
			resolvedLength += NumChars;
			if (resolved) 
			{
				strncat_s(resolved, resolvedCapacity, stack_line, NumChars);
			}
		}
		isPrevFrameInternal = isFrameInternal;

		if (!foundline)
			displacement = (DWORD)displacement64;
		NumChars = resolveFunction(programCounter, foundline ? &sourceInfo : NULL,
			displacement, functionName, stack_line, _countof(stack_line));

		if (NumChars > 0 && !isFrameInternal) 
		{
			resolvedLength += NumChars;
			if (resolved) 
			{
				strncat_s(resolved, resolvedCapacity, stack_line, NumChars);
			}
		}

	} // end for loop
	logMessage(resolved);

	return;
}