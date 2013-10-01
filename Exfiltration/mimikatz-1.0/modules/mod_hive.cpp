/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_hive.h"

mod_hive::nk_hdr* mod_hive::read_nk(nk_hdr *nk, hive *h, int offset )
{
	memcpy(nk, h->base + offset + 4, sizeof(nk_hdr));
	nk->key_name = (h->base + offset + 4 + 76);
	return nk;
}

mod_hive::lf_hdr* mod_hive::read_lf(lf_hdr *lf, hive *h, int offset )
{
	memcpy(lf, h->base+offset+4, sizeof(lf_hdr));
	lf->hr = (h->base+offset+4+4);
	return lf;
}

mod_hive::vk_hdr* mod_hive::read_vk(vk_hdr *vk, hive *h, int offset )
{
	memcpy(vk, h->base+offset+4, sizeof(vk_hdr));
	vk->value_name = (h->base+offset+4+20);
	return vk;
}

int* mod_hive::read_valuevector(int *value, hive *h, int offset, int size )
{
	memcpy(value, h->base+offset+4, size*sizeof(int));
	return value;
}

mod_hive::hashrecord* mod_hive::read_hr(hashrecord *hr, unsigned char *pos, int index )
{
	pos+=(8*index);
	memcpy(hr, pos, sizeof(hashrecord));
	return hr;
}


unsigned char*  mod_hive::read_data(hive *h, int offset )
{
	return ((unsigned char*) (h->base + offset + 4));
}

bool mod_hive::InitHive(hive *h)
{
	h->base = NULL;
	return true;
}

bool mod_hive::RegOpenHive(const wchar_t *filename, hive *h)
{
	bool reussite = false;
	FILE *hiveh;
	unsigned long hsize;

	if(_wfopen_s(&hiveh, filename, L"rb" ) == 0)
	{
		if(fseek(hiveh, 0, SEEK_END) == 0)
		{
			hsize = ftell(hiveh);
			h->base = new unsigned char[hsize];
			fseek(hiveh, 0, SEEK_SET);

			if(fread(h->base, hsize, 1, hiveh) == 1)
			{
				reussite = *((int *)h->base) == 0x66676572;
			}
		}
		fclose(hiveh);
	}
	return reussite;
}

bool mod_hive::RegCloseHive(hive *h )
{
	if(h->base != NULL)
	{
		delete[] h->base;
	}
	return true;
}


long mod_hive::parself(hive *h, char *t, unsigned long off )
{
	nk_hdr *n;
	lf_hdr *l;
	hashrecord *hr;

	int i;

	hr = (hashrecord*) malloc(sizeof(hashrecord));
	n = (nk_hdr*) malloc(sizeof(nk_hdr));
	l = (lf_hdr*) malloc(sizeof(lf_hdr));
	l = read_lf(l, h, off );

	for(i = 0; i < l->key_num; i++ )
	{
		hr = read_hr(hr, l->hr, i);
		n = read_nk(n, h, hr->nk_offset + 0x1000 );
		if(!memcmp( t, n->key_name, n->name_len ) && (strlen(t) == n->name_len))
		{
			free(n);
			free(l);
			return hr->nk_offset;
		}
	}
	free(n);
	free(l);
	return -1;
}

bool mod_hive::RegGetRootKey(hive *h, string *root_key)
{
	bool reussite = false;
	nk_hdr * n  = new nk_hdr();
	read_nk(n, h, 0x1020);
	if (n->id == NK_ID && n->type == NK_ROOT)
	{
		root_key->assign((const char *) n->key_name, n->name_len);
		reussite = true;
	}
	delete n;
	return reussite;
}

bool mod_hive::RegOpenKey(hive *h, string * path, nk_hdr **nr)
{
	bool reussite = false;

	nk_hdr *n = new nk_hdr();
	char *t, *tpath;
	unsigned long noff = 0;

	read_nk(n, h, 0x1020);

	if(n->id == NK_ID && n->type == NK_ROOT)
	{
		tpath = strdup(path->c_str());
		t = strtok(tpath, "\\");
		
		if(!memcmp(t, n->key_name, n->name_len))
		{
			t = strtok(NULL, "\\");
			while(t != NULL)
			{
				noff = parself(h, t, n->lf_off + 0x1000);
				if(noff != -1)
				{
					read_nk(n, h, noff + 0x1000);
					t = strtok( NULL, "\\" );
				}
				else
				{
					break;
				}
			}

			if(t == NULL && noff != 1)
			{
				memcpy(*nr, n, sizeof(nk_hdr));
				reussite = true;
			}
		}
		free(tpath);
	}

	delete n;
	return reussite;
}

bool mod_hive::RegQueryValue(hive *h, string *name, nk_hdr *nr, unsigned char **buff, int *len )
{
	bool reussite = false;

	vk_hdr *v = new vk_hdr();
	int * l = new int[nr->value_cnt];

	read_valuevector(l, h, nr->value_off + 0x1000, nr->value_cnt);

	for(unsigned int i = 0; i < nr->value_cnt; i++)
	{
		read_vk(v, h, l[i] + 0x1000);
		if((!memcmp(name->c_str(), v->value_name, name->size()) && v->name_len == name->size()) || (name == NULL && (v->flag & 1) == 0))
		{
			*len =  v->data_len & 0x0000FFFF; 
			*buff = new unsigned char[*len];
			if (*len < 5)
			{
				memcpy(*buff, &(v->data_off), *len);
			}
			else
			{
				memcpy(*buff, read_data(h, v->data_off + 0x1000), *len);
			}
			reussite = true;
			break;
		}
	}
	delete[] l;
	delete v;
	return reussite;
}

bool mod_hive::RegOpenKeyQueryValue(hive *h, string *path, string *name, unsigned char **buff, int *len)
{
	bool reussite = false;
	mod_hive::nk_hdr * nodeKey = new mod_hive::nk_hdr();
	if(mod_hive::RegOpenKey(h, path, &nodeKey))
	{
		reussite = mod_hive::RegQueryValue(h, name, nodeKey, buff, len);
	}
	delete nodeKey;
	return reussite;
}



bool mod_hive::RegEnumKey(hive *h, nk_hdr *nr, vector<string> * names)
{
	int index = 0;
	
	lf_hdr *lf = new lf_hdr();
	nk_hdr *nk = new nk_hdr();
	hashrecord *hr = new hashrecord();

	while(index < nr->subkey_num)
	{
		lf = read_lf(lf, h, nr->lf_off + 0x1000 );
		hr = read_hr(hr, lf->hr, index);
		nk = read_nk(nk, h, hr->nk_offset + 0x1000 );
		names->push_back(string(reinterpret_cast<char *>(nk->key_name), nk->name_len));
		index++;
	}

	delete lf, nk, hr;
	return !names->empty();
}
