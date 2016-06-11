#pragma once

#include <windows.h>
#include <vector>
#include <map>
#include <string>

namespace LDTools
{
	struct HeapContex
	{
		void* pHeap;
		std::vector<UINT_PTR> frames;
	};

	class RealDetector
	{
	public:
		static bool start(const char* moduleName);
		static bool stop();
		static bool check();
	private:
		static void* __cdecl _crtd_scalar_new(unsigned int size);
		static void* __cdecl _malloc(size_t size);
		static LPVOID __stdcall _HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size);
		static HANDLE   __stdcall _HeapCreate(DWORD options, SIZE_T initsize, SIZE_T maxsize);
		static void __cdecl _free(void* prt);
		static void __cdecl _crt_free_dbg(void* prt, size_t size);

		static bool patchImport(
			HMODULE importmodule,
			LPCSTR exportmodulename,
			LPCSTR exportmodulepath,
			LPCSTR importname,
			LPCVOID replacement);

		static bool unpatchImport(
			HMODULE importmodule,
			LPCSTR exportmodulename,
			LPCSTR exportmodulepath,
			LPCSTR importname,
			LPCVOID replacement);

		static bool m_trace;					// 是否正在检测
		static std::string m_moduleName;		// 处理的模块名字
		static std::map<void*, HeapContex> m_heapTrace;		// 调用栈
	};

	// 定义需要覆盖的函数
	typedef void* (__cdecl *malloc_t) (size_t);
	typedef void(__cdecl *free_t) (void*);
	typedef void(__cdecl *free_dbg_t) (void*, size_t);
	typedef void* (__cdecl *new_t) (size_t);
	typedef HANDLE(__stdcall *HeapCreate_t) (DWORD, SIZE_T, SIZE_T);

}