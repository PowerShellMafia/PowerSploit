/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_text.h"

PRTL_INIT_STRING mod_text::RtlInitString = reinterpret_cast<PRTL_INIT_STRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlInitString"));
PRTL_INIT_UNICODESTRING mod_text::RtlInitUnicodeString = reinterpret_cast<PRTL_INIT_UNICODESTRING>(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlInitUnicodeString"));

wstring mod_text::stringOfHex(const BYTE monTab[], DWORD maTaille, DWORD longueur)
{
	wostringstream monStream;
	for(DWORD j = 0; j < maTaille; j++)
	{
		monStream << setw(2) << setfill(wchar_t('0')) << hex << monTab[j];
		if(longueur != 0)
		{
			monStream << L' ';
			if ((j + 1) % longueur == 0)
				monStream << endl;
		}
	}
	return monStream.str();
}

wstring mod_text::stringOrHex(const BYTE monTab[], DWORD maTaille, DWORD longueur, bool ligne)
{
	wstring result;
	if(monTab && maTaille > 0)
	{
		int flags = IS_TEXT_UNICODE_ODD_LENGTH | IS_TEXT_UNICODE_STATISTICS /*| IS_TEXT_UNICODE_NULL_BYTES*/;
		if(IsTextUnicode(monTab, maTaille, &flags))
		{
			result.assign(reinterpret_cast<const wchar_t *>(monTab), maTaille / sizeof(wchar_t));
		}
		else
		{
			if(ligne)
				result.assign(L"\n");
			result.append(stringOfHex(monTab, maTaille, longueur));
		}
	}
	else result.assign(L"<NULL>");

	return result;
}

void mod_text::wstringHexToByte(wstring &maChaine, BYTE monTab[])
{
	wstringstream z;
	unsigned int temp;
	for(size_t i = 0; i < maChaine.size() / 2; i++)
	{
		z.clear();
		z << maChaine.substr(i * 2, 2); z >> hex >> temp;
		monTab[i] = temp;
	}
}

bool mod_text::wstr_ends_with(const wchar_t * str, const wchar_t * suffix)
{
	if(str && suffix)
	{
		size_t str_len = wcslen(str), suffix_len = wcslen(suffix);
		return wstr_ends_with(str, str_len, suffix, suffix_len);
	}
	return false;
}

bool mod_text::wstr_ends_with(const wchar_t * str, size_t str_len, const wchar_t * suffix, size_t suffix_len)
{
	if(str && suffix && (suffix_len <= str_len))
		return (_wcsnicmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
	return false;
}

wstring mod_text::stringOfSTRING(UNICODE_STRING maString)
{
	return wstring(maString.Buffer, maString.Length / sizeof(wchar_t));
}
string mod_text::stringOfSTRING(STRING maString)
{
	return string(maString.Buffer, maString.Length);
}

void mod_text::InitLsaStringToBuffer(LSA_UNICODE_STRING * LsaString, wstring &maDonnee, wchar_t monBuffer[])
{
	RtlCopyMemory(monBuffer, maDonnee.c_str(), (maDonnee.size() + 1) * sizeof(wchar_t));
	RtlInitUnicodeString(LsaString, monBuffer);
}

LUID mod_text::wstringsToLUID(wstring &highPart, wstring &lowPart)
{
	LUID monLUID = {0, 0};
	wstringstream z;
	z << highPart; z >> monLUID.HighPart;
	z.clear();
	z << lowPart; z >> monLUID.LowPart;
	return monLUID;
}