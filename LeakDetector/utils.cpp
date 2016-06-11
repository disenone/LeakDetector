#include "utils.h"
#include <windows.h>
#include <cstdarg>
#include <iostream>

MessageLogger plogger = nullptr;
MessageLoggerW ploggerw = nullptr;

void logMessage(const char* fmt, ...)
{
	char buffer[BUF_SIZE];
	va_list args;
	va_start(args, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, args);

	if (plogger)
		plogger(buffer);
	else
		printf(buffer);

	va_end(args);
}

void logMessage(const wchar_t* fmt, ...)
{
	WCHAR buffer[BUF_SIZE];
	va_list args;
	va_start(args, fmt);
	_vsnwprintf_s(buffer, sizeof(buffer), fmt, args);

	if (ploggerw)
		ploggerw(buffer);
	else
		wprintf_s(fmt, args);
	
	va_end(args);
}