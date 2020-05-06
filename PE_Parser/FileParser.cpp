#include "FileParser.h"
#include <cassert>

void FileParser::Reset()
{
	m_filename = "";
	m_handle = INVALID_HANDLE_VALUE;
	m_buffer = NULL;
	m_fileSize = 0;
	m_mapSize = 0;
	m_doshdr = NULL;
	m_pehdr = NULL;
	m_nthdr32 = NULL;
	m_nthdr64 = NULL;
	m_filehdr = NULL;
	m_opthdr32 = NULL;
	m_opthdr64 = NULL;
	m_sectbl = NULL;
	m_flags = 0;
	memset((void*)&m_res_sec, 0, sizeof(m_res_sec));
}

DWORD FileParser::getFileSize()
{
	return m_fileSize;
}

void* FileParser::displayErrorString(DWORD error)
{
	LPVOID lpMsgBuf;
	if (!FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)& lpMsgBuf,
		0,
		NULL))
	{
		return NULL;
	}

	return lpMsgBuf;
}

bool FileParser::openFile()
{
	m_handle = CreateFileA(
		m_filename.c_str(),    // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);                 // no attr. template

	if (m_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Unable to open file " << m_filename <<
			" for reading, err: " << GetLastError() << "\n";
		return false;
	}

	m_fileSize = GetFileSize(m_handle, NULL);
	return true;
}

bool FileParser::mapFile(char*& buf)
{
	bool ret = false;
	void* start = NULL;
	HANDLE hMapFile;

	hMapFile = CreateFileMapping(
		m_handle,
		NULL,                    // default security
		PAGE_READONLY,           // read/write access
		0,                       // maximum object size (high-order DWORD)
		0,                       // maximum object size (low-order DWORD)
		NULL);                   // name of mapping object

	if (hMapFile == NULL)
	{
		wchar_t* errorString = (wchar_t*)displayErrorString(GetLastError());
		printf("Could not create file mapping object, err: %d, msg: '%S'\n",
			GetLastError(), errorString);
		LocalFree(errorString);
		return false;
	}

	start = (void*)MapViewOfFile(
		hMapFile,		// handle to map object
		FILE_MAP_READ,	// read permission
		0, 0, 0);

	if (start == NULL)
	{
		std::cout << "Could not map view of file, err: " <<
			GetLastError() << std::endl;
	}
	else
	{
		buf = (char*)start;
		std::cout << "Successfully mapped file in process address space.\n";
		ret = true;
	}

	if ((hMapFile != 0) && (hMapFile != INVALID_HANDLE_VALUE))
		CloseHandle(hMapFile);

	if (!ret)
	{
		if (m_handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_handle);
			m_handle = INVALID_HANDLE_VALUE;
		}
	}

	return ret;
}

bool FileParser::loadFile()
{
	if (!openFile())
		return false;

	return mapFile(m_buffer);
}

bool FileParser::parse(const char* filepath)
{
	bool ret = false;

	// nullptr check
	if (!filepath)
		return false;

	// Empty filename
	if (!*filepath)
		return false;

	m_filename = filepath;

	if (!loadFile())
		return false;

	m_fileSize = getFileSize();
	m_doshdr = (IMAGE_DOS_HEADER*)(m_buffer);
	m_mapSize = m_fileSize < BUF_SIZE ? m_fileSize : BUF_SIZE;

	if ((!m_doshdr) || (m_mapSize < sizeof(IMAGE_DOS_HEADER)) || (m_doshdr->e_magic != IMAGE_DOS_SIGNATURE))
	{
		std::cout << m_filename << " is not a valid executable. Skipping." << std::endl;
		return false;
	}

	std::cout << m_filename << " is a valid EXE, with size [" << m_fileSize << "] bytes." << std::endl;

	m_pehdr = (IMAGE_NT_HEADERS*)((char*)m_doshdr + m_doshdr->e_lfanew);
	if (m_pehdr->Signature != IMAGE_NT_SIGNATURE)
	{
		std::cout << "Error: PE Signature not found !\n";
		return false;
	}

	if (m_pehdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		ret = ParsePE32();
	}
	else if (m_pehdr->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		ret = ParsePE64();
	}
	else
	{
		ret = false;
	}

	return ret;
}

enum
{
	PE_64_BIT,
	PE_32_BIT
};

bool FileParser::ParsePE32()
{
	std::cout << "The executble is 32-bit\n";

	m_flags = PE_32_BIT;
	m_nthdr32 = (IMAGE_NT_HEADERS32*)m_pehdr;
	m_filehdr = (IMAGE_FILE_HEADER*)(&(m_pehdr->FileHeader));
	m_opthdr32 = (IMAGE_OPTIONAL_HEADER32*)(&(m_pehdr->OptionalHeader));
	
	m_numSections = m_filehdr->NumberOfSections;
	std::cout << "\nNumber of Sections = " << m_numSections << std::endl;
	std::cout << "Subsystem = " << (int)(m_opthdr32->Subsystem) << std::endl;

	m_sectbl = (IMAGE_SECTION_HEADER*)((char*)(m_opthdr32)+ m_filehdr->SizeOfOptionalHeader);
	return (m_sectbl != NULL);
}

bool FileParser::ParsePE64()
{
	std::cout << "The executble is 64-bit\n";

	m_flags = PE_64_BIT;
	m_nthdr64 = (IMAGE_NT_HEADERS64*)m_pehdr;
	m_filehdr = (IMAGE_FILE_HEADER*)(&(m_pehdr->FileHeader));
	m_opthdr64 = (IMAGE_OPTIONAL_HEADER64*)(&(m_pehdr->OptionalHeader));

	m_numSections = m_filehdr->NumberOfSections;
	std::cout << "\nNumber of Sections = " << m_numSections << std::endl;
	std::cout << "Subsystem = " << m_opthdr64->Subsystem << std::endl;

	m_sectbl = (IMAGE_SECTION_HEADER*)((char*)(m_opthdr64)+ m_filehdr->SizeOfOptionalHeader);
	return (m_sectbl != NULL);
}

bool FileParser::getResourceSection()
{
	int i;

#ifdef _DEBUG
	for (int i = 0; i < m_numSections; i++)
	{
		char name[IMAGE_SIZEOF_SHORT_NAME + 1];
		strncpy_s(name, (char*)(m_sectbl[i].Name), IMAGE_SIZEOF_SHORT_NAME);
		name[IMAGE_SIZEOF_SHORT_NAME] = '\0';

		std::cout << "Section [" << i << "] --> [" << name << "]" << std::endl;
	}
#endif
	std::cout << "\n";

	// This rva is only recommended to be used to locate the Section header for a section.
	// The exact offset (or rva) of the section is inside the section header of the section.
	unsigned long rva = 0;
	if (m_flags == PE_64_BIT)
		rva = m_opthdr64->DataDirectory
		[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	else
		rva = m_opthdr32->DataDirectory
		[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;

	for (i = 0; i < m_numSections; i++)
	{
		unsigned long sec_end = m_sectbl[i].Misc.VirtualSize > m_sectbl[i].SizeOfRawData ?
			m_sectbl[i].Misc.VirtualSize :
			m_sectbl[i].SizeOfRawData;

		if ((rva >= m_sectbl[i].VirtualAddress) &&
			(rva < m_sectbl[i].VirtualAddress + sec_end))
		{
			strncpy_s(m_res_sec.hdr.name, (char*)(m_sectbl[i].Name), IMAGE_SIZEOF_SHORT_NAME);
			m_res_sec.hdr.name[IMAGE_SIZEOF_SHORT_NAME] = '\0';
			m_res_sec.hdr.sec_hdr_ptr = &m_sectbl[i];
			m_res_sec.datadir_rva = rva;
			m_res_sec.hdr.rva_start = m_sectbl[i].VirtualAddress;
			m_res_sec.hdr.rva_end = m_sectbl[i].VirtualAddress + sec_end;

			std::cout << "Section header index for Resource section "
				"is found at index [" << i << "] and name [" << m_res_sec.hdr.name << "].\n";
			break;
		}
	}

	if (i == m_numSections)
	{
		std::cout << "Error: Resource section header not found.\n";
		return false;
	}

	/*
	Note:
	====
	We have 2 ways to find the RVA of a particular section
	1) p_bin->opthdr64->DataDirectory[IMAGE_DIRECTORY_ENTRY_xxx].VirtualAddress;
	2) p_bin->sectbl[xxx_sec_hdr_index].VirtualAddress;

	The first RVA is only recommended to be used to locate the Section header for a section.
	Once the section header is found, the exact RVA of the section is inside that section header.

	Also note:
	Both these RVAs signify the offset (relative to the image base) of where the section will be
	loaded in the process Address space, when the loader will load the executable.
	*/
	if (m_res_sec.hdr.sec_hdr_ptr->VirtualAddress != m_res_sec.datadir_rva)
	{
		std::cout << "Resource section VA in DataDirectory = " << rva <<
			", and VA in SectionHdr = " << m_res_sec.hdr.sec_hdr_ptr->VirtualAddress << std::endl;
		assert(1);
	}
	
	m_res_sec.offset = m_res_sec.hdr.sec_hdr_ptr->PointerToRawData;
	std::cout << "Resource Section offset  = " << m_res_sec.offset << std::endl;

	return true;
}

bool FileParser::getDataDirAndEntry(
	char* base,
	unsigned long offset,
	IMAGE_RESOURCE_DIRECTORY** dir,
	IMAGE_RESOURCE_DIRECTORY_ENTRY** entry)
{
	bool ret = false;
	if (dir)
	{
		*dir = (IMAGE_RESOURCE_DIRECTORY*)(base + offset);
		if (*dir && entry)
		{
			*entry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)((char*)* dir + sizeof(IMAGE_RESOURCE_DIRECTORY));
			if (*entry)
				ret = true;
		}
	}
	return ret;
}

bool FileParser::parseResourceDir(int resource_id)
{
	bool ret = false;

	if (getResourceSection())
	{
		IMAGE_RESOURCE_DIRECTORY* root_dir;
		IMAGE_RESOURCE_DIRECTORY_ENTRY* root_dir_entry;
		IMAGE_RESOURCE_DIRECTORY_ENTRY* temp_dir_entry;
		bool found = false;
		int i;

		// PointerToRawData: This is the file-based offset of where the resource section resides in PE.
		// VirtualAddress: This is the RVA to where the loader should map the section.
		if (!getDataDirAndEntry((char*)m_doshdr, m_res_sec.hdr.sec_hdr_ptr->PointerToRawData,
			&m_res_sec.levels[0].dir, &m_res_sec.levels[0].entry))
		{
			return false;
		}

		root_dir = m_res_sec.levels[0].dir;
		root_dir_entry = m_res_sec.levels[0].entry;

		/* Locate required id type directory entry in root dir */
		for (i = 0, temp_dir_entry = root_dir_entry;
			i < (root_dir->NumberOfIdEntries + root_dir->NumberOfNamedEntries);
			i++, temp_dir_entry++)
		{
			if (temp_dir_entry->DataIsDirectory &&
				temp_dir_entry->Id == resource_id)
			{
				std::cout << "Level 1: Found resource " << resource_id << " at index i = " << i << "\n";
				found = true;
				break;
			}
		}

		if (!found)
		{
			std::cout << "Error: Resource " << resource_id << " not found in the EXE.\n";
			return false;
		}

		assert(temp_dir_entry->DataIsDirectory == 1);  // level 1 points to DataDirectory

		if (!getDataDirAndEntry((char*)root_dir, temp_dir_entry->OffsetToDirectory,
			&m_res_sec.levels[1].dir, &m_res_sec.levels[1].entry))
		{
			return false;
		}

		for (i = 0, temp_dir_entry = m_res_sec.levels[1].entry;
			i < (m_res_sec.levels[1].dir->NumberOfIdEntries + m_res_sec.levels[1].dir->NumberOfNamedEntries);
			i++, temp_dir_entry++)
		{
			std::cout << "Level 2: i = " << i << "\n";
			//assert(temp_dir_entry->DataIsDirectory == 1); // level 2 points to DataDirectory
			if (temp_dir_entry->DataIsDirectory == 1)
			{
				if (!getDataDirAndEntry((char*)root_dir, temp_dir_entry->OffsetToDirectory,
					&m_res_sec.levels[2].dir, &m_res_sec.levels[2].entry))
				{
					return false;
				}

				for (i = 0, temp_dir_entry = m_res_sec.levels[2].entry;
					i < (m_res_sec.levels[2].dir->NumberOfIdEntries + m_res_sec.levels[2].dir->NumberOfNamedEntries);
					i++, temp_dir_entry++)
				{
					assert(temp_dir_entry->DataIsDirectory == 0); // level 3 points to Data (leaf node)
					std::cout << "Level 3: i = " << i << " :: This is leaf node\n";

					m_res_sec.data = (IMAGE_RESOURCE_DATA_ENTRY*)
						((char*)root_dir + temp_dir_entry->OffsetToData);

					char* data_buffer = (char*)malloc(m_res_sec.data->Size);
					if (!data_buffer) return false;

					unsigned long data_offset = m_res_sec.data->OffsetToData - m_res_sec.datadir_rva;
					memcpy(data_buffer, (char*)root_dir + data_offset, m_res_sec.data->Size);
					m_res_sec.data_buffer = data_buffer;
					ret = true;
				}
			}
		}
	}

	return ret;
}

bool FileParser::parseVersionInfo(version_values_t& vi)
{
	bool found = false;
	inv_version_info_t* p_ver_info = (inv_version_info_t*)(m_res_sec.data_buffer);
	unsigned long size = m_res_sec.data->Size;
	//VS_VERSIONINFO* p_ver_info2 = (VS_VERSIONINFO*)data;

	if ('\0' != *(p_ver_info->key))
	{
		if (wcsncmp(p_ver_info->key, INV_VS_VERSION_STRING, INV_VS_VERSION_STRING_LEN) != 0)
		{
			std::wcout << L"Not matched, as it is: " << p_ver_info->key << std::endl;
			return false;
		}
	}
	std::cout << "\nVS_VERSION_INFO (size = " << size << ") -->\n";

	/* Align it to 32 bit boundry */
	unsigned long offset = offsetof(inv_version_info_t, opaque);
	INV_ALIGN_32BIT_BOUNDRY(offset);
	offset += p_ver_info->val_length;
	INV_ALIGN_32BIT_BOUNDRY(offset);

	char* tmp = ((char*)p_ver_info) + offset;
	inv_string_file_info_t* p_file_info = (inv_string_file_info_t*)tmp;

string_file_info:
	if ((NULL == p_file_info) || ('\0' == *(p_file_info->key)))
	{
		std::cout << "p_file_info->key is NULL\n";
		return false;
	}

	if (p_file_info->length > (sizeof(inv_version_info_t) +
		(size_t)(tmp - p_ver_info->opaque)))
	{
		return false;
	}

	if (p_file_info->length < sizeof(inv_string_file_info_t))
	{
		return false;
	}
	
	if (wcsncmp(p_file_info->key, INV_FILE_INFO_STRING, INV_FILE_INFO_STRING_LEN) != 0)
	{
		if ((wcsncmp(p_file_info->key, INV_VAR_FILE_INFO_STRING, INV_VAR_FILE_INFO_STRING_LEN) == 0) &&
			(p_file_info->length < size))
		{
			offset = p_file_info->length;
			INV_ALIGN_32BIT_BOUNDRY(offset);
			p_file_info = (inv_string_file_info_t*)(
				(char*)p_file_info + offset);
			goto string_file_info;
		}
		else
		{
			return false;
		}
	}

	unsigned long cur_size = offsetof(inv_string_file_info_t, opaque);
	INV_ALIGN_32BIT_BOUNDRY(cur_size);
	while (cur_size < p_file_info->length)
	{
		INT32 cur_str_tbl_size = 0;
		inv_string_tbl_t* p_tbl = (inv_string_tbl_t*)((char*)(p_file_info)+cur_size);
		cur_size += p_tbl->length;
		INV_ALIGN_32BIT_BOUNDRY(cur_size);
		if (p_tbl->length < sizeof(inv_string_tbl_t))
			return false;

		if (size < (ULONG)(((char*)p_tbl - (char*)p_ver_info) +
			p_tbl->length))
		{
			return false;
		}
			
		if (NULL == p_tbl->key + 2)
		{
			std::cout << "NULL p_tbl->key+2\n";
			return false;
		}

		/* We are interested only in english language version info */
		if (wcsncmp(p_tbl->key + 2, inv_ENG_LANG_CODE_STRING, 2) != 0)
		{
			/* Hack for some bad behaving apps */
			if (wcsncmp(p_tbl->key + 2, (L"00"), 2) != 0)
				continue;
		}

		cur_str_tbl_size = offsetof(inv_string_tbl_t, opaque);
		INV_ALIGN_32BIT_BOUNDRY(cur_str_tbl_size);
		while (cur_str_tbl_size < p_tbl->length)
		{
			wchar_t* key = NULL;
			wchar_t* value = NULL;
			inv_string_t* p_str = (inv_string_t*)((char*)(p_tbl)+cur_str_tbl_size);
			if (p_str->length < sizeof(inv_string_t))
				return false;

			if (size < (ULONG)(((char*)p_str - (char*)p_ver_info) +
				p_str->length))
				return false;

			cur_str_tbl_size += p_str->length;
			INV_ALIGN_32BIT_BOUNDRY(cur_str_tbl_size);

			if (p_str->type == 0)
			{
				continue;
			}

			key = (wchar_t*)p_str->opaque;
			offset = offsetof(inv_string_t, opaque);
			offset += wcslen(key) * sizeof(wchar_t) + sizeof(wchar_t);
			INV_ALIGN_32BIT_BOUNDRY(offset);
			value = (wchar_t*)((char*)p_str + offset);

			//std::wcout << std::wstring(key) << " = " << std::wstring(value) << std::endl;
			//m_res_sec.resources.emplace_back(std::make_pair(std::wstring(key), std::wstring(value)));
			vi.emplace_back(std::make_pair(std::wstring(key), std::wstring(value)));
			found = true;
		}
	}

	return found;
}

#if 0
const std::string FileParser::searchResourceByKey(const std::string& key)
{
	if (m_res_sec.resources.empty())
	{
		std::cout << "Vector m_res_sec.resources is empty !\n";
	}
	for (auto i : m_res_sec.resources)
	{
		//std::wcout << "key = " << i.first << " and value = " << i.second << std::endl;
		if (convert_to_string(i.first) == key)
		{
			return convert_to_string(i.second);
		}
		else
		{
			//std::cout << "Not Matched : passed key = " << key << " and stored key = " << convert_to_string(i.first) << std::endl;
		}
	}

	std::cout << "Resource value " << key << " not found in VS_VERSIONINFO.\n";
	return "";
}

const std::string FileParser::getOriginalFileName()
{
	return searchResourceByKey("OriginalFilename");
}
#endif