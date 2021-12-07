#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>
#include <wincrypt.h>

using namespace std;

// Методы заглушки, чтобы не вылетали ошибки при обращении к ним, т.к. они не определены у нас
void PrintError() {}
void writeln(string text, int i)
{
	cout << text << to_string(i) << endl;
}

#pragma comment(lib, "crypt32.lib")

class CryptoAPI
{
	HCRYPTPROV m_hCP = NULL;
	//public-private
	HCRYPTKEY m_hExchangeKey = NULL;
	//session
	HCRYPTKEY m_hSessionKey = NULL;
	//export
	HCRYPTKEY m_hExportKey = NULL;
public:

	HCRYPTKEY GetExchangeKey()
	{
		return m_hExchangeKey;
	}

	HCRYPTKEY GetSessionKey()
	{
		return m_hSessionKey;
	}

	HCRYPTKEY GetExportKey()
	{
		return m_hExportKey;
	}

	CryptoAPI()
	{
		if (!CryptAcquireContext(&m_hCP, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
			PrintError();
	}

	~CryptoAPI()
	{
		DestroyKeys();
		if (m_hCP)
		{
			if (!CryptReleaseContext(m_hCP, 0))
				PrintError();
		}
	}

	void GenKeyPair()
	{
		if (!CryptGenKey(m_hCP, CALG_RSA_KEYX, CRYPT_EXPORTABLE, &m_hExchangeKey))
			PrintError();
	}

	void GenSessionKey()
	{
		if (!CryptGenKey(m_hCP, CALG_AES_256, CRYPT_EXPORTABLE, &m_hSessionKey))
			PrintError();
	}

	void GenExportKey(const string& sPassword)
	{
		HCRYPTHASH hHash;
		if (!CryptCreateHash(m_hCP, CALG_SHA_256, NULL, 0, &hHash))
		{
			PrintError();
			return;
		}
		if (!CryptHashData(hHash, (BYTE*)sPassword.c_str(), sPassword.length(), 0))
		{
			PrintError();
			return;
		}

		if (!CryptDeriveKey(m_hCP, CALG_AES_256, hHash, CRYPT_EXPORTABLE, &m_hExportKey))
			PrintError();

		CryptDestroyHash(hHash);
	}

	void DestroyKey(HCRYPTKEY& hKey)
	{
		if (hKey)
		{
			if (!CryptDestroyKey(hKey))
				PrintError();
			hKey = NULL;
		}
	}

	void DestroyKeys()
	{
		DestroyKey(m_hExchangeKey);
		DestroyKey(m_hSessionKey);
		DestroyKey(m_hExportKey);
	}

	void DoExportKey(vector<char>& v, HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD dwType)
	{
		DWORD dwLen = 0;
		if (!CryptExportKey(hKey, hExpKey, dwType, 0, NULL, &dwLen))
		{
			PrintError();
			return;
		}
		v.resize(dwLen);
		if (!CryptExportKey(hKey, hExpKey, dwType, 0, (BYTE*)v.data(), &dwLen))
			PrintError();
		v.resize(dwLen);		// поскольку дл¤ некоторых ключей реальный размер экспортированных данных 
								// может быть меньше размера, необходимого дл¤ экспорта
	}

	void DoImportKey(vector<char>& v, HCRYPTKEY& hKey, HCRYPTKEY hPubKey, DWORD dwType)
	{
		if (!CryptImportKey(m_hCP, (BYTE*)v.data(), v.size(), hPubKey, CRYPT_EXPORTABLE, &hKey))
			PrintError();
	}

	void ExportPublicKey(vector<char>& v)
	{
		DoExportKey(v, m_hExchangeKey, NULL, PUBLICKEYBLOB);
	}

	void ExportPrivateKey(vector<char>& v)
	{
		DoExportKey(v, m_hExchangeKey, m_hExportKey, PRIVATEKEYBLOB);
	}

	void ExportSessionKey(vector<char>& v)
	{
		DoExportKey(v, m_hSessionKey, m_hExchangeKey, SIMPLEBLOB);
	}

	void ImportPublicKey(vector<char>& v)
	{
		DoImportKey(v, m_hExchangeKey, NULL, PUBLICKEYBLOB);
	}

	void ImportPrivateKey(vector<char>& v)
	{
		DoImportKey(v, m_hExchangeKey, m_hExportKey, PRIVATEKEYBLOB);
	}

	void ImportSessionKey(vector<char>& v)
	{
		DoImportKey(v, m_hSessionKey, NULL, SIMPLEBLOB);
	}

	void EncryptData(ifstream& in, ofstream& out, DWORD dwSize, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
			dwBlockLen -= 11;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			in.read(v.data(), dwBlockLen);
			DWORD dwRead = (DWORD)in.gcount();
			dwDone += dwRead;
			bDone = (dwDone == dwSize);
			dwDataLen = dwRead;
			if (!CryptEncrypt(hKey, NULL, bDone, 0, NULL, &dwDataLen, 0))
				PrintError();
			if (dwDataLen > v.size())
				v.resize(dwDataLen);
			if (!CryptEncrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead, v.size()))
				PrintError();
			out.write(v.data(), dwRead);
		}
	}

	void DecryptData(ifstream& in, ofstream& out, DWORD dwSize, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			in.read(v.data(), dwBlockLen);
			DWORD dwRead = (DWORD)in.gcount();
			dwDone += dwRead;
			bDone = (dwDone == dwSize);
			if (!CryptDecrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead))
				PrintError();
			out.write(v.data(), dwRead);
		}
	}

	void EncryptData(vector<char>& vIn, vector<char>& vOut, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
			dwBlockLen -= 11;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			DWORD dwRead = min(dwBlockLen, vIn.size() - dwDone);
			memcpy(v.data(), vIn.data() + dwDone, dwRead);
			dwDone += dwRead;
			bDone = (dwDone == vIn.size());
			dwDataLen = dwRead;
			if (!CryptEncrypt(hKey, NULL, bDone, 0, NULL, &dwDataLen, 0))
				PrintError();
			if (dwDataLen > v.size())
				v.resize(dwDataLen);
			if (!CryptEncrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead, v.size()))
				PrintError();
			vOut.insert(vOut.end(), v.begin(), v.begin() + dwRead);
		}
	}

	void DecryptData(vector<char>& vIn, vector<char>& vOut, HCRYPTKEY hKey = NULL, bool bRSA = false)
	{
		if (!hKey)
			hKey = m_hSessionKey;
		DWORD dwBlockLen = 0;
		DWORD dwDataLen = sizeof(DWORD);
		if (!CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLen, &dwDataLen, 0))
			PrintError();
		writeln("Block length: ", dwBlockLen);

		if (bRSA)
		{
			dwBlockLen >>= 3;
		}

		DWORD dwDone = 0;
		vector<char> v(dwBlockLen);

		bool bDone = false;
		while (!bDone)
		{
			DWORD dwRead = min(dwBlockLen, vIn.size() - dwDone);
			memcpy(v.data(), vIn.data() + dwDone, dwRead);
			dwDone += dwRead;
			bDone = (dwDone == vIn.size());
			if (!CryptDecrypt(hKey, NULL, bDone, 0, (BYTE*)v.data(), &dwRead))
				PrintError();
			vOut.insert(vOut.end(), v.begin(), v.begin() + dwRead);
		}
	}
};

void print(string text)
{
	cout << text;
}
void cw(string text)
{
	print(text);
	cout << endl;
}
// Метод генерирует ключи
void gen_all_keys(CryptoAPI& c, string& password) {

	c.GenKeyPair();
	c.GenExportKey(password);

	{
		vector<char> vPrivateKey;
		c.ExportPrivateKey(vPrivateKey);
		ofstream writer("private.txt", ios::binary);
		writer.write(vPrivateKey.data(), vPrivateKey.size());
		writer.close();
	}

	{
		vector<char> vPublicKey;
		c.ExportPublicKey(vPublicKey);
		ofstream writer("public.txt", ios::binary);
		writer.write(vPublicKey.data(), vPublicKey.size());
		writer.close();
	}

	cw("Keys generated and saved successfully!");
}
// Метод для выбора какой ключ использовать
void choose_and_import_key(CryptoAPI& c)
{
	while (true) {
		int is_pass = -1;
		cw("Enter [0] back to menu");
		cw("Enter [1] to use public key");
		cw("Enter [2] to use private key");
		print("Your choice: ");
		cin >> is_pass;

		if (is_pass == 1)
		{
			ifstream reader("public.txt", ios::binary);
			vector<char> vPublicKey(istreambuf_iterator<char>{reader}, {});
			c.ImportPublicKey(vPublicKey);
			reader.close();
			return;
		}
		else if (is_pass == 2)
		{
			string password = "";
			print("Enter private key password: ");
			cin >> password;
			c.GenExportKey(password);

			ifstream reader("private.txt", ios::binary);
			vector<char> vPrivateKey(istreambuf_iterator<char>{reader}, {});
			c.ImportPrivateKey(vPrivateKey);
			reader.close();
			return;
		}
		else cw("Invalid operation");
	}
}
// Метод для шифрации ТЕКСТА и СЕССИОННОГО КЛЮЧА - по итогу будет вызван дважды для обоих, храниться будут вместе
// Сперва шифрует сессионный ключ (ассиметрично по RSA)
// Получает его длину - пишет ее цифру(длину, типа 256) в файл
// после пишет разделитель ; - чтобы остановиться при чтении на нем и понимать какая длина у ключа
// дальше пишет ключ
// после берет зашифрованный(ассиметрично RSA) сессионный ключ и шифрует текст(симметрично AES_256)
// !!! Скорее всего RSA_256 используется, это не точно
// дописывает сразу после ключа получившийся зашифрованный текст
// сохраняет файл
void encrypt(CryptoAPI& crypto, string& filepath) {

	crypto.GenSessionKey();

	vector<char> vSessionKey, vEncryptedSessionKey;

	crypto.ExportSessionKey(vSessionKey);
	crypto.EncryptData(vSessionKey, vEncryptedSessionKey, crypto.GetExchangeKey(), true);

	string encrypted_file_name = "encrypted_" + filepath;
	char delimiter = ';';
	ofstream writer(encrypted_file_name, ios::binary);
	int key_size = vEncryptedSessionKey.size();
	writer << key_size << delimiter;
	writer.write(vEncryptedSessionKey.data(), vEncryptedSessionKey.size());

	ifstream reader(filepath, ios::binary);

	vector<char> vBaseText, vEncryptedBaseText;
	while (true)
	{
		char cSymbol;
		reader.get(cSymbol);
		if (reader.eof() == true)
			break;
		vBaseText.push_back(cSymbol);
	}

	crypto.EncryptData(vBaseText, vEncryptedBaseText);
	writer.write(vEncryptedBaseText.data(), vEncryptedBaseText.size());

	writer.close();
	reader.close();

	crypto.DestroyKeys();
	cout << "File [" << filepath << "] crypted successfully. Encrypted file name: [" << encrypted_file_name << "]" << endl;
}
// Метод для дешифрации ТЕКСТА и СЕССИОННОГО КЛЮЧА
// сперва считывает до разделителя цифры - это будет длина ключа
// преобразует считанные до разделителя цифры в int
// запускает цикл по этому число, то бишь по длине ключа
// считывает ключ, всю его длину
// не закрывая поток для вывода продолжает считывать с момента, где закончился ключ - там начался шифротекст
// считывает весь шифротекст
// сперва дешифрует сессионный ключ
// после по дешифрованному сессионному ключу - дешифрует текст
void decrypt(CryptoAPI& crypto, string& filepath)
{
	ifstream reader(filepath, ios::binary);
	string sTmpLength;
	vector<char> vEncryptedSessionKey;

	char delimiter = ';';
	while (true)
	{
		char cSymbol;
		reader.get(cSymbol);
		if (cSymbol == delimiter)
			break;
		sTmpLength.push_back(cSymbol);
	}

	int key_size = stoi(sTmpLength);
	for (int i = 0; i < key_size; ++i) {
		char key_symbol;
		reader.get(key_symbol);
		vEncryptedSessionKey.push_back(key_symbol);
	}
	vector<char> vDecryptedSessionKey;
	crypto.DecryptData(vEncryptedSessionKey, vDecryptedSessionKey, crypto.GetExchangeKey(), true);
	crypto.ImportSessionKey(vDecryptedSessionKey);

	vector<char> vEncryptedText, vDecryptedText;

	while (true)
	{
		char enc_text_symbol;
		reader.get(enc_text_symbol);
		if (reader.eof() == true)
			break;
		vEncryptedText.push_back(enc_text_symbol);
	}

	crypto.DecryptData(vEncryptedText, vDecryptedText);

	string decrypted_file_name = "decrypted_" + filepath;
	ofstream out(decrypted_file_name, ios::binary);
	out.write(vDecryptedText.data(), vDecryptedText.size());

	crypto.DestroyKeys();
	cout << "File [" << filepath << "] decrypted successfully! Decrypted file name [" << decrypted_file_name << "]" << endl;
}

void print_menu(int& operation)
{
	cw("0. Exit");
	cw("1. Gen key pair");
	cw("2. Encrypt Data");
	cw("3. Decrypt Data");
	print("Your choice: ");
	cin >> operation;
}

int main()
{
	setlocale(LC_ALL, "Russian");

	CryptoAPI c;
	while (true) {
		int operation = -1;
		print_menu(operation);
		if (operation == 0)
		{
			cw("Exit...");
			return 0;
		}
		else if (operation == 1)
		{
			string password;
			print("Enter pass to generate private key: ");
			cin >> password;
			gen_all_keys(c, password);
		}
		else if (operation == 2)
		{
			string filename_to_encrypt;
			choose_and_import_key(c);
			print("Enter file name to encrypt: ");
			cin >> filename_to_encrypt;
			encrypt(c, filename_to_encrypt);
		}
		else if (operation == 3)
		{
			string filename_to_decrypt;
			choose_and_import_key(c);
			print("Enter file name to decrypt: ");
			cin >> filename_to_decrypt;
			decrypt(c, filename_to_decrypt);
		}
		else cw("Invalid operation");
	}

	return 0;
}
