#include "RealDetector.h"
#include "LeakDetector.h"


using namespace std;
using namespace LDTools;

extern RealDetector leakd;

LeakDetector::LeakDetector(
	const char* moduleName /* = nullptr */,
	MessageLogger logger/* =nullptr */,
	MessageLoggerW loggerw/* = nullptr*/)
{
	if (logger)
	{
		plogger = logger;
	}
	if (loggerw)
	{
		ploggerw = loggerw;
	}
	m_initOk = leakd.start(moduleName);
	if (m_initOk)
	{
		logMessage("LeakDetector init success.\n");
	}
	else
	{
		logMessage("ERROR: LeakDetector init failed.\n");
	}
}

LeakDetector::~LeakDetector()
{
	leakd.stop();
}

bool LeakDetector::check()
{
	return leakd.check();
}

bool LeakDetector::isInitOk()
{
	return m_initOk;
}
