#pragma once
#include "FileParser.h"
#include <Windows.h>
#include <string>
#include <iostream>

#if 0
typedef struct _version_value_t
{
	DWORD           m_rva;        ///< start RVA of the current version value
	DWORD           m_length;     ///< length of the current version value
	DWORD           m_parent_ind; ///< index of the parent node
	std::string     m_key;        ///< key name
	bool            m_is_text;    ///< value type (1: text | 0 : binary)
	std::vector<BYTE> m_value;    ///< key value (either binary (if type == 0) | string (if type == 1))
} version_value_t;
using version_values_t = std::vector<version_value_t>;
#endif

class MetadataExtractor
{
public:
	bool Process(const char* path);
	void Reset();
	std::string convertWstringToString(const std::wstring& string_to_convert);
	const std::string searchVersionInfoByName(const std::string& Name);

private:
	FileParser			m_parser;
	version_values_t	m_version_info;
};
