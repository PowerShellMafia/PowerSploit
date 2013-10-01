/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_parseur.h"

vector<wstring> mod_parseur::parse(const wstring & line)
{
	vector<wstring> result;

	wstring          item;
	wstringstream    ss(line);

	while(ss >> item)
	{
		if (item[0] == L'"')
		{
			if (item[item.length() - 1] == L'"')
			{
				result.push_back(item.substr(1, item.length() -2));
			}
			else
			{
				wstring restOfItem;
				getline(ss, restOfItem, L'"');
				result.push_back(item.substr(1) + restOfItem);
			}
		}
		else
		{
			result.push_back(item);
		}
	}

	return result;
}

