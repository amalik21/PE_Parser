// PE_Parser.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "FileParser.h"
#include "MetadataExtractor.h"


int main()
{
	MetadataExtractor MEx;
	MEx.Process("c:\\windows\\system32\\cmd.exe");
	
	return 0;
}
