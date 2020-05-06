#pragma once
#include <string>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <tuple>
#include <locale>
#include <codecvt>

typedef struct
{
	char name[IMAGE_SIZEOF_SHORT_NAME + 1];
	unsigned long rva_start;
	unsigned long rva_end;
	IMAGE_SECTION_HEADER* sec_hdr_ptr;
} resource_section_header_t;

typedef struct
{
	IMAGE_RESOURCE_DIRECTORY* dir;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* entry;
}resource_tree_level_t;

typedef struct
{
	resource_section_header_t hdr;
	unsigned long datadir_rva;
	unsigned long offset;
	resource_tree_level_t levels[3];
	IMAGE_RESOURCE_DATA_ENTRY* data;
	char* data_buffer;
	std::vector<std::pair<std::wstring, std::wstring>> resources;
} resource_section_info_t;

using version_value_t = std::pair<std::wstring, std::wstring>;
using version_values_t = std::vector<version_value_t>;

#define INV_ALIGN_32BIT_BOUNDRY(i)		(i) = ((i) + 0x3) & (~0x3)
#define INV_VS_VERSION_STRING			(L"VS_VERSION_INFO")
#define INV_VS_VERSION_STRING_LEN		(sizeof (INV_VS_VERSION_STRING))/sizeof(wchar_t)

#define INV_FILE_INFO_STRING            (L"StringFileInfo")
#define INV_FILE_INFO_STRING_LEN		sizeof (INV_FILE_INFO_STRING)/sizeof(wchar_t)

#define INV_VAR_FILE_INFO_STRING        (L"VarFileInfo")
#define INV_VAR_FILE_INFO_STRING_LEN    sizeof (INV_VAR_FILE_INFO_STRING)/sizeof(wchar_t)

#define inv_ENG_LANG_CODE_STRING        (L"09")

#pragma pack(1)
typedef struct inv_version_info_st {
	UINT16 length;
	UINT16 val_length;
	UINT16 type;
	wchar_t key[INV_VS_VERSION_STRING_LEN];
	char* opaque;
} inv_version_info_t;
#pragma pack()

#pragma pack(1)
typedef struct inv_string_file_info_st {
	UINT16 length;
	UINT16 val_length;
	UINT16 type;
	wchar_t key[INV_FILE_INFO_STRING_LEN];
	char* opaque;
} inv_string_file_info_t;
#pragma pack()

#pragma pack(1)
typedef struct inv_string_tbl_st {
	UINT16 length;
	UINT16 val_length;
	UINT16 type;
	wchar_t key[8];
	char* opaque;
} inv_string_tbl_t;
#pragma pack()

#pragma pack(1)
typedef struct inv_string_st {
	UINT16 length;
	UINT16 val_length;
	UINT16 type;
	wchar_t opaque[1];
} inv_string_t;
#pragma pack()

class FileParser
{
public:
	void Reset();
	bool openFile();
	bool loadFile();
	bool parse(const char* filename);
	DWORD getFileSize();
	bool ParsePE32();
	bool ParsePE64();
	bool getResourceSection();
	bool parseResourceDir(int resource_id);
	bool parseVersionInfo(version_values_t& vi);
	const std::string getOriginalFileName();

private:
	static constexpr DWORD BUF_SIZE = (8 * 1024); // 8k
	std::string m_filename;
	char* m_buffer;

	HANDLE m_handle;
	DWORD m_fileSize;
	DWORD m_mapSize;
	int m_flags;
	int m_numSections;

	IMAGE_DOS_HEADER* m_doshdr;
	IMAGE_NT_HEADERS* m_pehdr;
	IMAGE_NT_HEADERS32* m_nthdr32;			/* Nt header */
	IMAGE_NT_HEADERS64* m_nthdr64;		
	IMAGE_FILE_HEADER* m_filehdr;			/* File header */
	IMAGE_OPTIONAL_HEADER32* m_opthdr32;	/* Optional header */
	IMAGE_OPTIONAL_HEADER64* m_opthdr64;	/* Optional header - 64 bit */
	IMAGE_SECTION_HEADER* m_sectbl;			/* Section table */
	resource_section_info_t	m_res_sec;

private:
	bool mapFile(char*& buf);
	void* displayErrorString(DWORD err);
	bool getDataDirAndEntry(
		char* base,
		unsigned long offset,
		IMAGE_RESOURCE_DIRECTORY** dir,
		IMAGE_RESOURCE_DIRECTORY_ENTRY** entry);
	//const std::string searchResourceByKey(const std::string& key);
	//std::string convert_to_string(const std::wstring& string_to_convert);
};
