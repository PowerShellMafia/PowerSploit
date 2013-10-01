/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
using namespace std;

#define NK_ID	0x6B6E
#define NK_ROOT 0x2c
#define LF_ID	0x666C

class mod_hive
{
public:
	typedef struct _hive
	{
		unsigned char *base;
	} hive;

	typedef struct _nk_hdr 
	{
		short int	id;
		short int	type;
		int	t1, t2;
		int	unk1;
		int	parent_off;
		int	subkey_num;
		int	unk2;
		int	lf_off;
		int	unk3;
		/* unsigned */
		unsigned int value_cnt;
		int	value_off;
		int	sk_off;
		int	classname_off;
		int	unk4[4];
		int	unk5;
		short int	name_len;
		short int	classname_len;
		unsigned char	*key_name; 
	} nk_hdr;

	typedef struct _hashrecord 
	{
		int	nk_offset;
		char	keyname[4];
	} hashrecord;

	typedef struct _lf_hdr 
	{
		short int	id;
		short int	key_num;
		unsigned char *hr;
	} lf_hdr;

	typedef struct _vk_hdr 
	{
		short int  id;
		short int  name_len;
		int data_len;
		int data_off;
		int data_type;
		short int  flag;
		short int unk1;
		unsigned char *value_name;
	} vk_hdr;

	static bool InitHive(hive *h);
	static bool RegOpenHive(const wchar_t * filename, hive *h);
	static bool RegCloseHive(hive *h);
	static bool RegGetRootKey(hive *h, string *root_key);
	static bool RegOpenKey(hive *h, string *path, nk_hdr **nr);
	static bool RegQueryValue(hive *h, /*char *name*/ string *name, nk_hdr *nr, unsigned char **buff, int *len);
	static bool RegOpenKeyQueryValue(hive *h, string *path, string *name, unsigned char **buff, int *len);
	static bool RegEnumKey(hive *h, nk_hdr *nr, vector<string> * names);

	static long parself(hive *h, char *t, unsigned long off);
	static unsigned char* read_data(hive *h, int offset);
private:
	static nk_hdr* read_nk(nk_hdr *nk, hive *h, int offset); 
	static lf_hdr* read_lf(lf_hdr *lf, hive *h, int offset);
	static vk_hdr* read_vk(vk_hdr *vk, hive *h, int offset);
	static hashrecord* read_hr(hashrecord *hr, unsigned char *pos, int index);
	static int* read_valuevector(int *value, hive *h, int offset, int size);
	
};
