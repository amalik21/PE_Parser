#include "MetadataExtractor.h"
#include "FileParser.h"

void MetadataExtractor::Reset()
{
	m_parser.Reset();
	m_version_info.clear();
}

std::string MetadataExtractor::convertWstringToString(const std::wstring& string_to_convert)
{
	//setup converter
	using convert_type = std::codecvt_utf8<wchar_t>;
	std::wstring_convert<convert_type, wchar_t> converter;

	//use converter (.to_bytes: wstr->str, .from_bytes: str->wstr)
	return converter.to_bytes(string_to_convert);
}

const std::string MetadataExtractor::searchVersionInfoByName(const std::string& Name)
{
	const std::string& key = Name;
	for (auto i : m_version_info)
	{
		//std::wcout << "key = " << i.first << " and value = " << i.second << std::endl;
		if (convertWstringToString(i.first) == key)
		{
			return convertWstringToString(i.second);
		}
		else
		{
			//std::cout << "Not Matched : passed key = " << key << " and stored key = " << 
				//convertWstringToString(i.first) << std::endl;
		}
	}

	std::cout << "Resource value " << key << " not found in VS_VERSIONINFO.\n";
	return "";
}

bool MetadataExtractor::Process(const char* filepath)
{
	Reset();

	if (!filepath || !*filepath || !m_parser.parse(filepath))
		return false;

	//auto resource_ok = m_parser.parseResourceDir((int)RT_VERSION);
	auto resource_ok = m_parser.parseResourceDir((int)RT_ICON);
	auto version_ok = resource_ok ? m_parser.parseVersionInfo(m_version_info) : false;
	auto originalName = version_ok ? searchVersionInfoByName("OriginalFilename") : "";
	auto companyName = version_ok ? searchVersionInfoByName("CompanyName") : "";
	std::cout << "Original Filename = " << originalName << " and companyName = " << companyName << std::endl;
	return true;
}