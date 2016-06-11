// LeakDetectorTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "LeakDetector.h"
#include <iostream>
using namespace std;

int main()
{
	auto ld = LDTools::LeakDetector("LeakDetectorTest.exe");

	{
		char* c = new char[12];
		int* i = new int[4];
	}

    return 0;
}

