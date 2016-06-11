#pragma once
#include "utils.h"

namespace LDTools
{

	class LeakDetector
	{
	public:
		EXPORT LeakDetector(
			const char* moduleName = nullptr,
			MessageLogger logger = nullptr, 
			MessageLoggerW loggerw = nullptr);

		EXPORT ~LeakDetector();

		EXPORT bool check();

		EXPORT bool isInitOk();

	private:
		bool m_initOk = false;
	};



}	// namepace LDTools



