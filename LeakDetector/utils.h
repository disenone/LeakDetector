#pragma once

#if defined(_WIN32)
#ifdef LEAK_DETECTOR_EXPORTS
#define EXPORT __declspec(dllexport)
#else
#define EXPORT __declspec(dllimport)
#endif
#else
#define EXPORT
#endif

#define BUF_SIZE 10240

typedef void (*MessageLogger)(const char*);
typedef void(*MessageLoggerW)(const wchar_t*);
extern MessageLogger plogger;
extern MessageLoggerW ploggerw;

void logMessage(const char* fmt, ...);
void logMessage(const wchar_t* fmt, ...);