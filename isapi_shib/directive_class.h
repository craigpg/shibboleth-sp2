#include <string>
#include <tchar.h>
#define STR_PENDING_DELETION "(Pending Removal)"

using namespace std;

class Directive
{
public:
	
	Directive() {
	}
	
	~Directive() {
	}
	
	Directive(unsigned int which_directive) {
		Init_Directive(which_directive);
	}
	
	string name;
	unsigned short type; 
	string value;
	string new_value;
	string defined_in;
	string description;
	string bound_val[NUM_BOUND_VAL];
	string MachineName;
	unsigned int d_index;
	
	bool Set_Path(string new_path)
	{
		if (new_path.length() && new_path.at(0) == '/') {
			path = new_path;
		} else {
			path = "/";
			path += new_path;
		}
		Get_Value();
		return true;
	}
	
	bool WriteValue(string RegPath)
	{
		if (type == D_BOUND_INT || type == D_FREE_INT) {
			return WriteRegInt(RegPath.c_str(), name.c_str(), new_value.c_str());
		} else {
			return WriteRegString(RegPath.c_str(), name.c_str(), new_value.c_str());
		}
	}

	void Directive::Init_Directive(unsigned int w) {
		
		if (w >= NUM_DIRECTIVES) {
			return;
		}
		d_index = w;
		name  = directives[w].name;
		type  = directives[w].type;
		value = directives[w].value;
		defined_in = directives[w].defined_in;
		description = directives[w].description;
		for (int i=0;i<NUM_BOUND_VAL;i++) {
			bound_val[i] = directives[w].bound_val[i];
		}
	}

	void DeleteValue()
	{
		new_value = STR_PENDING_DELETION;
	}

	bool Directive::DeleteRegVal(string Key) 
	{
		HKEY hKey;
		
		if ((hKey=OpenKey(Key.c_str(),KEY_ALL_ACCESS))) {
			if (RegDeleteValue(hKey,name.c_str()) == ERROR_SUCCESS) {
				return true;
			}
		}
		return false;
	}

private:
	
	string path;
		
	HKEY Directive::OpenKey(LPCTSTR szKey, REGSAM samDesired) {
		
		HKEY hKey,rhKey;
		_TCHAR localname[MAX_PATH];
		DWORD lsize = MAX_PATH;
		
		//Support for Remote Registries 
		GetComputerName(localname,&lsize);
		if (!_tcsicmp(localname,MachineName.c_str())) {
			rhKey = HKEY_LOCAL_MACHINE;
		}else {
			if (RegConnectRegistry(MachineName.c_str(),HKEY_LOCAL_MACHINE, &rhKey) != ERROR_SUCCESS) {
				//MessageBox(hwndDlg,L"Error opening remote registry.  Values displayed may not be accurate.",L"Error",MB_ICONERROR);
			}
		}
		
		if (samDesired == KEY_READ) {
			// Open existing key.
			if( RegOpenKeyEx(rhKey,
				szKey,
				0,
				samDesired,
				&hKey) != ERROR_SUCCESS) 
			{
				return NULL ;
			}
			
		} else {
			// Create and open key and subkey.
			if( RegCreateKeyEx(rhKey,
				szKey,
				0, NULL, REG_OPTION_NON_VOLATILE,
				samDesired, NULL,
				&hKey, NULL) != ERROR_SUCCESS) 
			{
				return NULL ;
			}
		}
		
		return hKey;
	
	}
	
	void Directive::ReadValAsString(string key, LPCTSTR defined_in_val) {
		HKEY hKey;
		char RegBuff[MAX_REG_BUFF];
		long debug;
		DWORD dwRead=MAX_REG_BUFF*sizeof(char);
		
		if (hKey = OpenKey(key.c_str(),KEY_READ)) {
			if ((debug = RegQueryValueEx (hKey,name.c_str(), NULL, NULL, (LPBYTE)RegBuff, &dwRead)) == ERROR_SUCCESS) {
				if (type == D_FREE_INT || type == D_BOUND_INT) {
					char tmpw[22];
					value = itoa(*(DWORD *)RegBuff,tmpw,10);
				} else {
					value = RegBuff;
				}
				defined_in = defined_in_val;
			} 
			RegCloseKey (hKey); 
		} 
	}
	
	bool Directive::WriteRegInt(const _TCHAR* szKey,
		const _TCHAR* szValueName,
		const _TCHAR* szValue)
	{
		HKEY hKey;
		DWORD value;
		
		if (!(hKey=OpenKey(szKey,KEY_ALL_ACCESS)))
			return FALSE;
		
		// Set the Value.
		if (szValue != NULL)
		{
			value = _ttoi(szValue);
			RegSetValueEx(hKey, szValueName, 0, REG_DWORD,
				(BYTE *)&value,
				sizeof(DWORD)) ;
		}
		
		RegCloseKey(hKey) ;
		return TRUE ;
	}
	

	bool Directive::WriteRegString(const _TCHAR* szKey,
		const _TCHAR* szValueName,
		const _TCHAR* szValue)
	{
		HKEY hKey;
		
		if (!(hKey=OpenKey(szKey,KEY_ALL_ACCESS)))
			return FALSE;
		
		// Set the Value.
		if (szValue != NULL)
		{
			RegSetValueEx(hKey, szValueName, 0, REG_SZ,
				(BYTE *)szValue,
				((DWORD)_tcslen(szValue)+1)*sizeof(_TCHAR)) ;
		}
		
		RegCloseKey(hKey);
		return TRUE ;
	}

	void Directive::Get_Value() {
		
		string key, node, defined_in_val;
		size_t pos = 0;
		size_t opos = 0;
		char done = 0;
		
		value = directives[d_index].value;
		defined_in = directives[d_index].defined_in;

		key = SHIB_DEFAULT_WEB_KEY;

		do {

			pos = path.find('/',opos);  // while we still have a '/' left to deal with
			
			if (pos != string::npos) {
				node = path.substr(opos,pos-opos);
			}
			else {
				node = path.substr(opos);
				done = 1;
			}
			if (defined_in_val[defined_in_val.length()-1] != '/') {
				defined_in_val += "/";
				key += "\\";
			}

			defined_in_val += node;
			key += node;
			
			ReadValAsString(key,defined_in_val.c_str());
			opos = pos+1;
			
		} while (!done);
	}
};
