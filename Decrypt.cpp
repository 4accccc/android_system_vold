/*
 * Copyright (C) 2016 - 2020 The TeamWin Recovery Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Decrypt.h"
#include "FsCrypt.h"
#include <fscrypt/fscrypt.h>

#include <map>
#include <string>
#include <vector>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <keyutils.h>
#include "Weaver1.h"
#include "cutils/properties.h"

#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fstream>
#include <future>
#include <algorithm>
#include <chrono>

#include <android/binder_manager.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <base/threading/platform_thread.h>
#include <android/hardware/confirmationui/1.0/types.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>

#include <binder/IServiceManager.h>
#include <binder/IPCThreadState.h>
#include <hardware/hw_auth_token.h>

#include <gatekeeper/GateKeeperResponse.h>

// Direct Keymaster HIDL interface (bypassing keystore service)
#include "Keymaster.h"
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <android/hardware/keymaster/4.0/types.h>
#include <keymasterV4_0/authorization_set.h>
#include <keymasterV4_0/keymaster_utils.h>

extern "C" {
#include "crypto_scrypt.h"
}

#include "fscrypt_policy.h"
#include "fscrypt-common.h"
#include "HashPassword.h"
#include "KeystoreInfo.hpp"
#include "KeyStorage.h"
#include "android/os/IVold.h"

// Direct Keymaster HIDL namespace
namespace km_hidl = ::android::hardware::keymaster::V4_0;
using android::hardware::gatekeeper::V1_0::GatekeeperResponse;
using GKResponse = ::android::service::gatekeeper::GateKeeperResponse;

static bool lookup_ref_key_internal(std::map<userid_t, android::fscrypt::EncryptionPolicy> key_map, const uint8_t* policy, uint8_t size, uint8_t hex_size, userid_t* user_id) {
	char policy_string_hex[hex_size];
	char key_map_hex[hex_size];
	bytes_to_hex(policy, size, policy_string_hex);

    for (std::map<userid_t, android::fscrypt::EncryptionPolicy>::iterator it=key_map.begin(); it!=key_map.end(); ++it) {
		bytes_to_hex(reinterpret_cast<const uint8_t*>(&it->second.key_raw_ref[0]), size, key_map_hex);
		std::string key_map_hex_string = std::string(key_map_hex);
		if (key_map_hex_string == policy_string_hex) {
            *user_id = it->first;
            return true;
        }
    }
    return false;
}

extern "C" bool lookup_ref_key(fscrypt_policy* fep, uint8_t* policy_type) {
	userid_t user_id = 0;
	std::string policy_type_string;

	uint8_t *descriptor = get_policy_descriptor(fep);
	uint8_t hex_size = get_policy_size(fep, true);
	uint8_t size = get_policy_size(fep, false);
	char policy_hex[hex_size];
	bytes_to_hex(descriptor, size, policy_hex);
	if (std::strncmp((const char*)descriptor, de_key_raw_ref.c_str(), size) == 0) {
		policy_type_string = std::to_string(fep->version) + SYSTEM_DE_FSCRYPT_POLICY;
		memcpy(policy_type, policy_type_string.data(), policy_type_string.size());
		return true;
	}
	if (!lookup_ref_key_internal(s_de_policies, descriptor, size, hex_size, &user_id)) {
		if (!lookup_ref_key_internal(s_ce_policies, descriptor, size, hex_size, &user_id)) return false;
		else policy_type_string = std::to_string(fep->version) + USER_CE_FSCRYPT_POLICY + std::to_string(user_id);

	} else policy_type_string = std::to_string(fep->version) + USER_DE_FSCRYPT_POLICY + std::to_string(user_id);

	memcpy(policy_type, policy_type_string.data(), policy_type_string.size());
	printf("storing policy type: %s\n", policy_type);
	return true;
}

extern "C" bool lookup_ref_tar(fscrypt_policy *fep, uint8_t* policy) {
	if (fep->version < FSCRYPT_POLICY_V1 || fep->version > FSCRYPT_POLICY_V2) {
		printf("Unexpected version: %d\n", (int)fep->version);
 		return false;
 	}
	uint8_t hex_size, size, *descriptor;
	hex_size = get_policy_size(fep, true);
	size = get_policy_size(fep, false);
	descriptor = get_policy_descriptor(fep);
	std::string policy_type_string = std::string((char *) descriptor);
	char policy_hex[hex_size];
	bytes_to_hex(descriptor, size, policy_hex);
	if (policy_type_string.substr(1, 2) == SYSTEM_DE_KEY) {
		memcpy(policy, de_key_raw_ref.data(), de_key_raw_ref.size());
		return true;
	}

	std::string raw_ref;

	if (policy_type_string.substr(1, 1) == USER_DE_KEY) {
		userid_t user_id = std::stoi(policy_type_string.substr(3, 4).c_str());
		if (lookup_key_ref(s_de_policies, user_id, &raw_ref)) {
			memcpy(policy, raw_ref.data(), raw_ref.size());
		} else {
			return false;
		}
	} else if (policy_type_string.substr(1, 1) == USER_CE_KEY) {
		userid_t user_id = std::stoi(policy_type_string.substr(3, 4).c_str());
		if (lookup_key_ref(s_ce_policies, user_id, &raw_ref)) {
			memcpy(policy, raw_ref.data(), raw_ref.size());
		} else {
			return false;
		}
	} else {
		printf("unknown policy type: %s\n", descriptor);
		return false;
	}
	return true;
}

extern "C" bool Decrypt_DE() {
	printf("[DEBUG] Decrypt_DE: ENTER\n");
	printf("Attempting to initialize DE keys\n");
	printf("[DEBUG] Decrypt_DE: calling fscrypt_initialize_systemwide_keys\n");
	if (!fscrypt_initialize_systemwide_keys()) { // this deals with the overarching device encryption
		printf("[DEBUG] Decrypt_DE: fscrypt_initialize_systemwide_keys FAILED\n");
		printf("fscrypt_initialize_systemwide_keys returned fail\n");
		return false;
	}
	if (!fscrypt_init_user0()) {
		printf("fscrypt_init_user0 returned fail\n");
		return false;
	}
	return true;
}

// Crappy functions for debugging, please ignore unless you need to debug
// void output_hex(const std::string& in) {
// 	const char *buf = in.data();
// 	char hex[in.size() * 2 + 1];
// 	unsigned int index;
// 	for (index = 0; index < in.size(); index++)
// 		sprintf(&hex[2 * index], "%02X", buf[index]);
// }

// void output_hex(const char* buf, const int size) {
// 	char hex[size * 2 + 1];
// 	int index;
// 	for (index = 0; index < size; index++)
// 		sprintf(&hex[2 * index], "%02X", buf[index]);
// 	printf("%s", hex);
// }

// void output_hex(const unsigned char* buf, const int size) {
// 	char hex[size * 2 + 1];
// 	int index;
// 	for (index = 0; index < size; index++)
// 		sprintf(&hex[2 * index], "%02X", buf[index]);
// 	printf("%s", hex);
// }

// void output_hex(std::vector<uint8_t>* vec) {
// 	char hex[3];
// 	unsigned int index;
// 	for (index = 0; index < vec->size(); index++) {
// 		sprintf(&hex[0], "%02X", vec->at(index));
// 		printf("%s", hex);
// 	}
// }

/* This is the structure of the data in the password data (*.pwd) file which the structure can be found
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#187 */
struct password_data_struct {
	int password_type;
	unsigned char scryptN;
	unsigned char scryptR;
	unsigned char scryptP;
	int salt_len;
	void* salt;
	int handle_len;
	void* password_handle;
};

bool Get_Spblob_Data(const std::string& spblob_path, const std::string& handle_str, const std::string& suffix, const std::string& tag, std::string *data) {
	bool found_file = false;
	std::string file = spblob_path + handle_str + suffix;
	if (android::vold::pathExists(file)) {
		if (!android::base::ReadFileToString(file, data)) {
			printf("Failed to read '%s'\n", file.c_str());
		} else
			found_file = true;
	} else {
		printf("trying to read %s_file data with leading 0\n", tag.c_str());
		std::vector<std::string> file_paths = {
			spblob_path + "0" + handle_str + suffix,
			spblob_path + "00" + handle_str + suffix
		};
		for (auto& file : file_paths) {
			if (!android::base::ReadFileToString(file, data)) {
				printf("Failed to read '%s'\n", file.c_str());
			} else {
				found_file = true;
				break;
			}
		}
	}
	return found_file;
}

/* C++ replacement for
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#764 */
bool Get_Password_Data(const std::string& spblob_path, const std::string& handle_str, password_data_struct *pwd) {
	std::string pwd_data;
	if (!Get_Spblob_Data(spblob_path, handle_str, ".pwd", "password", &pwd_data))
		return false;
	// output_hex(pwd_data.data(), pwd_data.size());printf("\n");
	const int* intptr = (const int*)pwd_data.data();
	pwd->password_type = *intptr;
	endianswap(&pwd->password_type);
	//printf("password type %i\n", pwd->password_type); // 2 was PIN, 1 for pattern, 2 also for password, -1 for default password
	const unsigned char* byteptr = (const unsigned char*)pwd_data.data() + sizeof(int);
	pwd->scryptN = *byteptr;
	byteptr++;
	pwd->scryptR = *byteptr;
	byteptr++;
	pwd->scryptP = *byteptr;
	byteptr++;
	intptr = (const int*)byteptr;
	pwd->salt_len = *intptr;
	endianswap(&pwd->salt_len);
	if (pwd->salt_len != 0) {
		pwd->salt = malloc(pwd->salt_len);
		if (!pwd->salt) {
			printf("Get_Password_Data malloc salt\n");
			return false;
		}
		memcpy(pwd->salt, intptr + 1, pwd->salt_len);
		intptr++;
		byteptr = (const unsigned char*)intptr;
		byteptr += pwd->salt_len;
	} else {
		printf("Get_Password_Data salt_len is 0\n");
		return false;
	}
	intptr = (const int*)byteptr;
	pwd->handle_len = *intptr;
	endianswap(&pwd->handle_len);
	if (pwd->handle_len != 0) {
		pwd->password_handle = malloc(pwd->handle_len);
		if (!pwd->password_handle) {
			printf("Get_Password_Data malloc password_handle\n");
			return false;
		}
		memcpy(pwd->password_handle, intptr + 1, pwd->handle_len);
	} else {
		printf("Get_Password_Data handle_len is 0\n");
		// Not an error if using weaver
	}
	return true;
}

/* C++ replacement for
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#765
 * called here
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1050 */
bool Get_Password_Token(const password_data_struct *pwd, const std::string& Password, unsigned char* password_token) {
	if (!password_token) {
		printf("password_token is null\n");
		return false;
	}
	unsigned int N = 1 << pwd->scryptN;
	unsigned int r = 1 << pwd->scryptR;
	unsigned int p = 1 << pwd->scryptP;
	//printf("N %i r %i p %i\n", N, r, p);
	int ret = crypto_scrypt(reinterpret_cast<const uint8_t*>(Password.data()), Password.size(),
                          reinterpret_cast<const uint8_t*>(pwd->salt), pwd->salt_len,
                          N, r, p,
                          password_token, 32);
	if (ret != 0) {
		printf("scrypt error\n");
		return false;
	}
	return true;
}

// Data structure for the *.weaver file, see Get_Weaver_Data below
struct weaver_data_struct {
	unsigned char version;
	int slot;
};

/* C++ replacement for
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#501
 * called here
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#768 */
bool Get_Weaver_Data(const std::string& spblob_path, const std::string& handle_str, weaver_data_struct *wd) {
	printf("Get_Weaver_Data\n");
	std::string weaver_file = spblob_path + handle_str + ".weaver";
	std::string weaver_data;
	if (!android::base::ReadFileToString(weaver_file, &weaver_data)) {
		printf("Failed to read '%s'\n", weaver_file.c_str());
		return false;
	}
	// output_hex(weaver_data.data(), weaver_data.size());printf("\n");
	const unsigned char* byteptr = (const unsigned char*)weaver_data.data();
	wd->version = *byteptr;
	// printf("weaver version %i\n", wd->version);
	const int* intptr = (const int*)weaver_data.data() + sizeof(unsigned char);
	wd->slot = *intptr;
	//endianswap(&wd->slot); not needed
	// printf("weaver slot %i\n", wd->slot);
	return true;
}

namespace android {
namespace keystore {

#define SYNTHETIC_PASSWORD_VERSION_V1 1
#define SYNTHETIC_PASSWORD_VERSION_V2 2
#define SYNTHETIC_PASSWORD_VERSION_V3 3
#define SYNTHETIC_PASSWORD_PASSWORD_BASED 0
#define SYNTHETIC_PASSWORD_KEY_PREFIX "USRSKEY_synthetic_password_"
#define USR_PRIVATE_KEY_PREFIX "USRPKEY_synthetic_password_"
#define PASSWORD_TOKEN_SIZE 32

static std::string mKey_Prefix;

void copySqliteDb() {
	std::string keystore_path = "/tmp/misc/keystore/";
	mkdir("/tmp/misc", 0755);
	mkdir("/tmp/misc/keystore", 0755);
	std::string dst = keystore_path + "persistent.sqlite";
	std::string src = "/data/misc/keystore/persistent.sqlite";
	std::ifstream srcif(src.c_str(), std::ios::binary);
	std::ofstream dstof(dst.c_str(), std::ios::binary);
	printf("copying '%s' to '%s'\n", src.c_str(), dst.c_str());
	dstof << srcif.rdbuf();
	srcif.close();
	dstof.close();
}

/* The keystore alias subid is sometimes the same as the handle, but not always.
 * We scan keystore files and copy them to temp folder for operations. */
bool Find_Keystore_Alias_SubID_And_Prep_Files(const userid_t user_id, std::string& keystoreid, const std::string& handle_str) {
	char path_c[PATH_MAX];
	sprintf(path_c, "/data/misc/keystore/user_%d", user_id);
	char user_dir[PATH_MAX];
	sprintf(user_dir, "user_%d", user_id);
	std::string source_path = "/data/misc/keystore/";
	source_path += user_dir;
	std::string handle_sub = handle_str;
	while (handle_sub.substr(0,1) == "0") {
		std::string temp = handle_sub.substr(1);
		handle_sub = temp;
	}
	mKey_Prefix = "";

	mkdir("/tmp/misc", 0755);
	mkdir("/tmp/misc/keystore", 0755);
	std::string destination_path = "/tmp/misc/keystore/";
	destination_path += user_dir;
	if (mkdir(destination_path.c_str(), 0755) && errno != EEXIST) {
		printf("failed to mkdir '%s' %s\n", destination_path.c_str(), strerror(errno));
		return false;
	}
	destination_path += "/";

	DIR* dir = opendir(source_path.c_str());
	if (!dir) {
		printf("Error opening '%s'\n", source_path.c_str());
		return false;
	}
	source_path += "/";

	struct dirent* de = 0;
	size_t prefix_len = strlen(SYNTHETIC_PASSWORD_KEY_PREFIX);
	bool found_subid = false;
	bool has_pkey = false;

	while ((de = readdir(dir)) != 0) {
		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;
		if (!found_subid) {
			size_t len = strlen(de->d_name);
			if (len <= prefix_len)
				continue;
			if (strstr(de->d_name, SYNTHETIC_PASSWORD_KEY_PREFIX) && !has_pkey)
				mKey_Prefix = SYNTHETIC_PASSWORD_KEY_PREFIX;
			else if (strstr(de->d_name, USR_PRIVATE_KEY_PREFIX)) {
				mKey_Prefix = USR_PRIVATE_KEY_PREFIX;
				has_pkey = true;
			} else
				continue;
			if (strstr(de->d_name, handle_sub.c_str())) {
				keystoreid = handle_sub;
				printf("keystoreid matched handle_sub: '%s'\n", keystoreid.c_str());
				found_subid = true;
			} else {
				std::string file = de->d_name;
				std::size_t found = file.find_last_of("_");
				if (found != std::string::npos) {
					keystoreid = file.substr(found + 1);
				}
			}
		}
		std::string src = source_path;
		src += de->d_name;
		std::ifstream srcif(src.c_str(), std::ios::binary);
		std::string dst = destination_path;
		dst += de->d_name;
		std::size_t source_uid = dst.find("1000");
		if (source_uid != std::string::npos)
			dst.replace(source_uid, 4, "0");
		std::ofstream dstof(dst.c_str(), std::ios::binary);
		printf("copying '%s' to '%s'\n", src.c_str(), dst.c_str());
		dstof << srcif.rdbuf();
		srcif.close();
		dstof.close();
	}
	closedir(dir);
	if (!found_subid && !mKey_Prefix.empty() && !keystoreid.empty())
		found_subid = true;
	return found_subid;
}

/* C++ replacement for function of the same name using direct Keymaster HIDL
 * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#867
 * returning an empty string indicates an error */
std::string unwrapSyntheticPasswordBlob(const std::string& spblob_path, const std::string& handle_str, const userid_t user_id,
	const void* application_id, const size_t application_id_size, uint32_t auth_token_len) {
	printf("[SPBLOB] Attempting to unwrap synthetic password blob (Direct Keymaster HIDL)\n");
	std::string disk_decryption_secret_key = "";

	std::string keystore_alias_subid;
	std::string key_blob;

	// Find the keystore key file and read the key blob
	char path_c[PATH_MAX];
	bool found_key = false;

	// Debug: list all files in keystore directories
	for (const char* ks_path : {"/data/misc/keystore", "/data/misc/keystore/user_0"}) {
		DIR* d = opendir(ks_path);
		if (d) {
			printf("[SPBLOB] Files in %s:\n", ks_path);
			struct dirent* e;
			while ((e = readdir(d)) != nullptr) {
				if (e->d_name[0] != '.') {
					printf("[SPBLOB]   %s\n", e->d_name);
				}
			}
			closedir(d);
		}
	}

	// Check for master key file
	std::string masterkey;
	if (android::base::ReadFileToString("/data/misc/keystore/.masterkey", &masterkey)) {
		printf("[SPBLOB] Found .masterkey file, size=%zu\n", masterkey.size());
	} else {
		printf("[SPBLOB] No .masterkey file found\n");
	}

	// Try user's keystore first, then user 0
	for (int try_user : {(int)user_id, 0}) {
		sprintf(path_c, "/data/misc/keystore/user_%d", try_user);
		DIR* dir = opendir(path_c);
		if (!dir) continue;

		std::string handle_sub = handle_str;
		while (handle_sub.substr(0,1) == "0" && handle_sub.length() > 1) {
			handle_sub = handle_sub.substr(1);
		}

		struct dirent* de;
		while ((de = readdir(dir)) != nullptr) {
			std::string filename = de->d_name;
			if (filename.find(SYNTHETIC_PASSWORD_KEY_PREFIX) != std::string::npos ||
			    filename.find(USR_PRIVATE_KEY_PREFIX) != std::string::npos) {
				if (filename.find(handle_sub) != std::string::npos) {
					std::string key_file = std::string(path_c) + "/" + filename;
					printf("[SPBLOB] Found key file: %s\n", key_file.c_str());
					if (android::base::ReadFileToString(key_file, &key_blob)) {
						found_key = true;
						keystore_alias_subid = handle_sub;
						break;
					}
				}
			}
		}
		closedir(dir);
		if (found_key) break;
	}

	if (!found_key || key_blob.empty()) {
		printf("[SPBLOB] Failed to find keystore key file\n");
		return disk_decryption_secret_key;
	}
	printf("[SPBLOB] Read key blob, size=%zu\n", key_blob.size());

	// Debug: dump first 48 bytes of key blob to understand format
	if (key_blob.size() >= 48) {
		printf("[SPBLOB] Key blob header (first 48 bytes):\n");
		const unsigned char* kb = (const unsigned char*)key_blob.data();
		printf("[SPBLOB]   Bytes 0-15:  ");
		for (int i = 0; i < 16; i++) printf("%02x ", kb[i]);
		printf("\n[SPBLOB]   Bytes 16-31: ");
		for (int i = 16; i < 32; i++) printf("%02x ", kb[i]);
		printf("\n[SPBLOB]   Bytes 32-47: ");
		for (int i = 32; i < 48; i++) printf("%02x ", kb[i]);
		printf("\n");
		// Interpret as keystore blob format
		printf("[SPBLOB]   Keystore blob: version=%d type=%d flags=%d info=%d\n",
			kb[0], kb[1], kb[2], kb[3]);
	}

	// Parse keystore blob format to extract actual keymaster blob
	// Format: version(1) + type(1) + flags(1) + info(1) + [IV(16) + tag(16) + length(4)] + data
	if (key_blob.size() >= 4) {
		const unsigned char* kb = (const unsigned char*)key_blob.data();
		uint8_t ks_version = kb[0];
		uint8_t ks_type = kb[1];
		uint8_t ks_flags = kb[2];

		printf("[SPBLOB] Parsing keystore blob: version=%d type=%d flags=0x%02x\n",
			ks_version, ks_type, ks_flags);

		// For blobv3 (version=3) with TYPE_KEYMASTER_10 (type=4)
		if (ks_version == 3 && ks_type == 4) {
			// Check if encrypted (flags & 1) or super-encrypted (flags & 2)
			bool is_encrypted = (ks_flags & 0x01) || (ks_flags & 0x02);

			if (!is_encrypted || ks_flags == 8) {
				// Not encrypted by master key, or flags=8 (special case)
				// Try different offsets to find the keymaster blob
				// Blob has lots of zeros from byte 4-38, data seems to start around byte 39
				size_t offsets[] = {4, 39, 40, 36, 44};
				for (size_t offset : offsets) {
					if (key_blob.size() > offset) {
						std::string km_blob = key_blob.substr(offset);
						printf("[SPBLOB] Trying keymaster blob at offset %zu, size=%zu\n",
							offset, km_blob.size());

						// Dump first 16 bytes of extracted blob
						if (km_blob.size() >= 16) {
							printf("[SPBLOB]   First 16 bytes: ");
							for (int i = 0; i < 16; i++)
								printf("%02x ", (unsigned char)km_blob[i]);
							printf("\n");
						}
					}
				}

				// Analyze the internal structure after keystore header
				// Bytes 36-39 appear to be length (big endian), data starts at 40
				// But offset 40 gives us "01 02 00 00" which might be another header
				// Try offset 44 where actual keymaster blob data might start

				// Print more of the blob for analysis
				if (key_blob.size() >= 64) {
					printf("[SPBLOB] Extended hex dump (bytes 36-63):\n");
					const unsigned char* kb = (const unsigned char*)key_blob.data();
					printf("[SPBLOB]   36-51: ");
					for (int i = 36; i < 52; i++) printf("%02x ", kb[i]);
					printf("\n[SPBLOB]   52-63: ");
					for (int i = 52; i < 64; i++) printf("%02x ", kb[i]);
					printf("\n");
				}

				// Try multiple offsets and test each with keymaster
				printf("[SPBLOB] Testing different offsets with keymaster...\n");
				size_t try_offsets[] = {0, 4, 40, 44};
				for (size_t offset : try_offsets) {
					if (key_blob.size() > offset + 16) {
						std::string test_blob = key_blob.substr(offset);
						printf("[SPBLOB] Testing offset %zu (size=%zu): ", offset, test_blob.size());

						// Quick test with getKeyCharacteristics
						android::vold::Keymaster km_test;
						if (km_test) {
							android::vold::km::AuthorizationSet hw, sw;
							km_test.getKeyCharacteristics(test_blob, &hw, &sw);
						}
					}
				}

				// Use offset 40 (confirmed working with getKeyCharacteristics)
				size_t best_offset = 40;
				if (key_blob.size() > best_offset) {
					key_blob = key_blob.substr(best_offset);
					printf("[SPBLOB] Using keymaster blob from offset %zu, new size=%zu\n", best_offset, key_blob.size());
				}
			} else {
				printf("[SPBLOB] Keystore blob is encrypted (flags=0x%02x), cannot decrypt without master key\n", ks_flags);
				return disk_decryption_secret_key;
			}
		}
	}

	// Read the data from the .spblob file
	std::string spblob_data;
	if (!Get_Spblob_Data(spblob_path, handle_str, ".spblob", "spblob", &spblob_data))
		return disk_decryption_secret_key;

	unsigned char* byteptr = (unsigned char*)spblob_data.data();
	if (*byteptr != SYNTHETIC_PASSWORD_VERSION_V2 && *byteptr != SYNTHETIC_PASSWORD_VERSION_V1
			&& *byteptr != SYNTHETIC_PASSWORD_VERSION_V3) {
		printf("[SPBLOB] Unsupported synthetic password version %i\n", *byteptr);
		return disk_decryption_secret_key;
	}
	const unsigned char* synthetic_password_version = byteptr;
	byteptr++;
	if (*byteptr != SYNTHETIC_PASSWORD_PASSWORD_BASED) {
		printf("[SPBLOB] spblob data is not SYNTHETIC_PASSWORD_PASSWORD_BASED\n");
		return disk_decryption_secret_key;
	}
	byteptr++; // Now we're pointing to the blob data itself

	if (*synthetic_password_version == SYNTHETIC_PASSWORD_VERSION_V2
			|| *synthetic_password_version == SYNTHETIC_PASSWORD_VERSION_V3) {
		printf("[SPBLOB] spblob v2/v3 - using direct Keymaster HIDL\n");

		// Extract IV and cipher text from spblob
		const unsigned char* iv = byteptr;
		const unsigned char* cipher_text = byteptr + 12;
		size_t cipher_text_size = spblob_data.size() - 14; // 2 bytes header + 12 bytes IV

		printf("[SPBLOB] IV size=12, cipher_text_size=%zu\n", cipher_text_size);

		// Get Keymaster device
		android::vold::Keymaster keymaster;
		if (!keymaster) {
			printf("[SPBLOB] Failed to get Keymaster device\n");
			return disk_decryption_secret_key;
		}

		// First, try to get key characteristics to understand the key type
		printf("[SPBLOB] Checking key characteristics...\n");
		android::vold::km::AuthorizationSet hwEnforced, swEnforced;
		if (keymaster.getKeyCharacteristics(key_blob, &hwEnforced, &swEnforced)) {
			printf("[SPBLOB] Got key characteristics successfully\n");
		} else {
			printf("[SPBLOB] Failed to get key characteristics (may need upgrade)\n");
		}

		// Build authorization set for AES-GCM decryption
		// Use android::vold::km namespace which is keymint AIDL types
		using android::vold::km::AuthorizationSetBuilder;
		using android::vold::km::TAG_PURPOSE;
		using android::vold::km::TAG_ALGORITHM;
		using android::vold::km::TAG_BLOCK_MODE;
		using android::vold::km::TAG_PADDING;
		using android::vold::km::TAG_NONCE;
		using android::vold::km::TAG_MAC_LENGTH;
		using android::vold::km::KeyPurpose;
		using android::vold::km::Algorithm;
		using android::vold::km::BlockMode;
		using android::vold::km::PaddingMode;
		using android::vold::KeymasterOperation;

		std::vector<uint8_t> nonce_vec(iv, iv + 12);
		auto params = AuthorizationSetBuilder()
			.Authorization(TAG_PURPOSE, KeyPurpose::DECRYPT)
			.Authorization(TAG_ALGORITHM, Algorithm::AES)
			.Authorization(TAG_BLOCK_MODE, BlockMode::GCM)
			.Authorization(TAG_PADDING, PaddingMode::NONE)
			.Authorization(TAG_NONCE, nonce_vec)
			.Authorization(TAG_MAC_LENGTH, 128);

		android::vold::km::AuthorizationSet outParams;

		// Read auth token from file written by gatekeeper verification
		android::hardware::keymaster::V4_0::HardwareAuthToken authToken;
		bool hasAuthToken = false;
		if (auth_token_len > 0) {
			std::string auth_token_data;
			if (android::base::ReadFileToString("/auth_token", &auth_token_data)) {
				printf("[SPBLOB] Read auth_token file, size=%zu\n", auth_token_data.size());
				// Parse hw_auth_token_t format (69 bytes):
				// version(1) + challenge(8) + user_id(8) + authenticator_id(8) +
				// authenticator_type(4) + timestamp(8) + hmac(32)
				if (auth_token_data.size() >= 69) {
					const uint8_t* p = (const uint8_t*)auth_token_data.data();
					uint8_t version = p[0];
					p += 1;
					memcpy(&authToken.challenge, p, 8); p += 8;
					memcpy(&authToken.userId, p, 8); p += 8;
					memcpy(&authToken.authenticatorId, p, 8); p += 8;
					uint32_t authType;
					memcpy(&authType, p, 4); p += 4;
					// Convert from network byte order
					authType = ntohl(authType);
					authToken.authenticatorType = static_cast<android::hardware::keymaster::V4_0::HardwareAuthenticatorType>(authType);
					uint64_t timestamp;
					memcpy(&timestamp, p, 8); p += 8;
					// Convert from network byte order (swap bytes for 64-bit)
					timestamp = ((timestamp & 0x00000000000000FFULL) << 56) |
					            ((timestamp & 0x000000000000FF00ULL) << 40) |
					            ((timestamp & 0x0000000000FF0000ULL) << 24) |
					            ((timestamp & 0x00000000FF000000ULL) << 8) |
					            ((timestamp & 0x000000FF00000000ULL) >> 8) |
					            ((timestamp & 0x0000FF0000000000ULL) >> 24) |
					            ((timestamp & 0x00FF000000000000ULL) >> 40) |
					            ((timestamp & 0xFF00000000000000ULL) >> 56);
					authToken.timestamp = timestamp;
					authToken.mac.resize(32);
					memcpy(authToken.mac.data(), p, 32);
					hasAuthToken = true;
					printf("[SPBLOB] Parsed auth token: challenge=%llu, userId=%llu, authType=%d, timestamp=%llu\n",
						(unsigned long long)authToken.challenge,
						(unsigned long long)authToken.userId,
						(int)authToken.authenticatorType,
						(unsigned long long)authToken.timestamp);
				} else {
					printf("[SPBLOB] Auth token too small: %zu bytes\n", auth_token_data.size());
				}
			} else {
				printf("[SPBLOB] Failed to read /auth_token\n");
			}
		}

		// Begin decryption operation with key blob
		KeymasterOperation op;
		if (hasAuthToken) {
			printf("[SPBLOB] Using begin() with auth token\n");
			op = keymaster.begin(key_blob, params, &outParams, authToken);
		} else {
			printf("[SPBLOB] Using begin() without auth token\n");
			op = keymaster.begin(key_blob, params, &outParams);
		}

		// Handle KEY_REQUIRES_UPGRADE (-33 in HIDL) by upgrading the key and retrying
		// Use raw value comparison since keymint AIDL ErrorCode values differ from HIDL
		int error_code = static_cast<int>(op.getErrorCode());
		printf("[SPBLOB] Keymaster begin returned error code: %d\n", error_code);

		if (!op && error_code == -33) {  // -33 = KEY_REQUIRES_UPGRADE in HIDL keymaster
			printf("[SPBLOB] Key requires upgrade (error -33), attempting upgrade...\n");

			// Build upgrade params (empty for most cases)
			android::vold::km::AuthorizationSet upgradeParams;
			std::string upgraded_key_blob;

			if (keymaster.upgradeKey(key_blob, upgradeParams, &upgraded_key_blob)) {
				printf("[SPBLOB] Key upgrade succeeded, size=%zu\n", upgraded_key_blob.size());
				key_blob = upgraded_key_blob;

				// Retry begin with upgraded key (with auth token if available)
				if (hasAuthToken) {
					op = keymaster.begin(key_blob, params, &outParams, authToken);
				} else {
					op = keymaster.begin(key_blob, params, &outParams);
				}
				if (op) {
					printf("[SPBLOB] Retry after upgrade succeeded\n");
				} else {
					printf("[SPBLOB] Retry after upgrade failed: %d\n", static_cast<int>(op.getErrorCode()));
				}
			} else {
				printf("[SPBLOB] Key upgrade failed\n");
				return disk_decryption_secret_key;
			}
		}

		if (!op) {
			printf("[SPBLOB] Keymaster begin failed: %d\n", error_code);
			return disk_decryption_secret_key;
		}
		printf("[SPBLOB] Keymaster begin succeeded\n");

		// Update with cipher text
		std::string input_data((const char*)cipher_text, cipher_text_size);
		std::string keystore_result;
		if (!op.updateCompletely(input_data, &keystore_result)) {
			printf("[SPBLOB] Keymaster update failed\n");
			return disk_decryption_secret_key;
		}
		printf("[SPBLOB] Keymaster update succeeded, result_size=%zu\n", keystore_result.size());

		// Finish operation
		std::string finish_output;
		if (!op.finish(&finish_output)) {
			printf("[SPBLOB] Keymaster finish failed\n");
			return disk_decryption_secret_key;
		}
		keystore_result += finish_output;
		printf("[SPBLOB] Keymaster finish succeeded, total_size=%zu\n", keystore_result.size());

		if (keystore_result.size() < 12) {
			printf("[SPBLOB] Keymaster result too small\n");
			return disk_decryption_secret_key;
		}

		// Second decrypt with OpenSSL AES/GCM using personalized application ID
		const unsigned char* intermediate_iv = (const unsigned char*)keystore_result.data();
		const unsigned char* intermediate_cipher_text = (const unsigned char*)keystore_result.data() + 12;
		int intermediate_cipher_size = keystore_result.size() - 12;

		void* personalized_application_id = PersonalizedHashBinary(PERSONALISATION_APPLICATION_ID,
			(const char*)application_id, application_id_size);
		if (!personalized_application_id) {
			printf("[SPBLOB] Unable to obtain personalized_application_id\n");
			return disk_decryption_secret_key;
		}

		OpenSSL_add_all_ciphers();
		int actual_size = 0, final_size = 0;
		EVP_CIPHER_CTX *d_ctx = EVP_CIPHER_CTX_new();
		const unsigned char* key = (const unsigned char*)personalized_application_id;
		EVP_DecryptInit(d_ctx, EVP_aes_256_gcm(), key, intermediate_iv);

		unsigned char* secret_key = (unsigned char*)malloc(intermediate_cipher_size);
		if (!secret_key) {
			printf("[SPBLOB] malloc failure on secret key\n");
			free(personalized_application_id);
			EVP_CIPHER_CTX_free(d_ctx);
			return disk_decryption_secret_key;
		}

		EVP_DecryptUpdate(d_ctx, secret_key, &actual_size, intermediate_cipher_text, intermediate_cipher_size);
		unsigned char tag[AES_BLOCK_SIZE];
		EVP_CIPHER_CTX_ctrl(d_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
		EVP_DecryptFinal_ex(d_ctx, secret_key + actual_size, &final_size);
		EVP_CIPHER_CTX_free(d_ctx);
		free(personalized_application_id);

		int secret_key_real_size = actual_size - 16;
		if (secret_key_real_size <= 0) {
			printf("[SPBLOB] Invalid secret key size: %d\n", secret_key_real_size);
			free(secret_key);
			return disk_decryption_secret_key;
		}

		// Generate disk decryption key
		if (*synthetic_password_version == SYNTHETIC_PASSWORD_VERSION_V3) {
			disk_decryption_secret_key = PersonalizedHashSP800(PERSONALIZATION_FBE_KEY,
				PERSONALISATION_CONTEXT, (const char*)secret_key, secret_key_real_size);
		} else {
			disk_decryption_secret_key = PersonalizedHash(PERSONALIZATION_FBE_KEY,
				(const char*)secret_key, secret_key_real_size);
		}
		printf("[SPBLOB] Successfully generated disk decryption secret key\n");
		free(secret_key);
		return disk_decryption_secret_key;
	}
	return disk_decryption_secret_key;
}

// /* C++ replacement for
//  * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#992
//  * called here
//  * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#813 */
bool Get_Secdis(const std::string& spblob_path, const std::string& handle_str, std::string& secdis_data) {
	return Get_Spblob_Data(spblob_path, handle_str, ".secdis", "secdis", &secdis_data);
	// output_hex(secdis_data.data(), secdis_data.size());printf("\n");
}

// // C++ replacement for https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1033
userid_t fakeUid(const userid_t uid) {
    return 100000 + uid;
}

bool Is_Weaver(const std::string& spblob_path, const std::string& handle_str) {
	printf("Is_Weaver\n");
	std::string weaver_file = spblob_path + handle_str + ".weaver";
	struct stat st;
	if (stat(weaver_file.c_str(), &st) == 0)
		return true;
	return false;
}

bool Free_Return(bool retval, void* weaver_key, password_data_struct* pwd) {
	printf("Free_Return\n");
	if (weaver_key)
		free(weaver_key);
	if (pwd->salt)
		free(pwd->salt);
	if (pwd->password_handle)
		free(pwd->password_handle);
	return retval;
}

bool Decrypt_CE_storage(const userid_t user_id, int token, const std::string& secret) {
	printf("Attempting to unlock user storage\n");
	int flags = android::os::IVold::STORAGE_FLAG_CE;
	if (!fscrypt_unlock_user_key(user_id, token, secret)) {
		printf("fscrypt_unlock_user_key returned fail\n");
		return false;
	}
	printf("Attempting to prepare user storage\n");
	if (!fscrypt_prepare_user_storage("", user_id, 0, flags)) {
		printf("failed to fscrypt_prepare_user_storage\n");
		return false;
	}
	printf("User %i Decrypted Successfully!\n", user_id);
	return true;
}

// /* Decrypt_User_Synth_Pass is the TWRP C++ equivalent to spBasedDoVerifyCredential
//  * https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/LockSettingsService.java#1998 */
bool Decrypt_User_Synth_Pass(const userid_t user_id, const std::string& Password) {
	printf("Attempting to decrypt user's synthetic password\n");
	bool retval = false;
	void* weaver_key = NULL;
	password_data_struct pwd;
	pwd.salt = NULL;
	pwd.salt_len = 0;
	pwd.password_handle = NULL;
	pwd.handle_len = 0;
	char application_id[PASSWORD_TOKEN_SIZE + SHA512_DIGEST_LENGTH];
	uint32_t auth_token_len = 0;
	std::string secret; // this will be the disk decryption key that is sent to vold
	int token = 0; // there is no token used for this kind of decrypt, key escrow is handled by weaver
	char spblob_path_char[PATH_MAX];
	sprintf(spblob_path_char, "/data/system_de/%d/spblob/", user_id);
	std::string spblob_path = spblob_path_char;
	long handle = 0;
	// Get the handle: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/LockSettingsService.java#2017
	KeystoreInfo keystore_info;
	std::string handle_str = keystore_info.getHandle(user_id);
	// Now we begin driving unwrapPasswordBasedSyntheticPassword from: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#758
	// First we read the password data which contains scrypt parameters
	// printf("pwd N %i R %i P %i salt ", pwd.scryptN, pwd.scryptR, pwd.scryptP); output_hex((char*)pwd.salt, pwd.salt_len); printf("\n");
	// printf("Password: '%s'\n", Password.c_str());
	// The password token is the password scrypted with the parameters from the password data file
	unsigned char password_token[PASSWORD_TOKEN_SIZE];
	if (Password != "!") {
		if (!Get_Password_Data(spblob_path, handle_str, &pwd)) {
			printf("Failed to Get_Password_Data\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		printf("fscrypt::GetPassword_Token\n");
		if (!Get_Password_Token(&pwd, Password, &password_token[0])) {
			printf("Failed to Get_Password_Token\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
	} else {
		android::keystore::copySqliteDb(); // early copy db for keystore
		std::string defpassword = "default-password";
		memcpy(password_token, defpassword.data(), defpassword.length());
	}
	// output_hex(&password_token[0], PASSWORD_TOKEN_SIZE);printf("\n");
	if (Is_Weaver(spblob_path, handle_str)) {
		printf("using weaver\n");
		// BEGIN PIXEL 2 WEAVER
		// Get the weaver data from the .weaver file which tells us which slot to use when we ask weaver for the escrowed key
		// https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#768
		weaver_data_struct wd;
		if (!Get_Weaver_Data(spblob_path, handle_str, &wd)) {
			printf("Failed to get weaver data\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		// The weaver key is the the password token prefixed with "weaver-key" padded to 128 with nulls with the password token appended then SHA512
		// https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#1059
		weaver_key = PersonalizedHashBinary(PERSONALISATION_WEAVER_KEY, (char*)&password_token[0], PASSWORD_TOKEN_SIZE);
		if (!weaver_key) {
			printf("malloc error getting weaver_key\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		// Now we start driving weaverVerify: https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#343
		// Called from https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#776
		android::vold::Weaver weaver;
		if (!weaver) {
			printf("Failed to get weaver service\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		// Get the key size from weaver service
		uint32_t weaver_key_size = 0;
		if (!weaver.GetKeySize(&weaver_key_size)) {
			printf("Failed to get weaver key size\n");
			return Free_Return(retval, weaver_key, &pwd);
		} else {
			printf("weaver key size is %u\n", weaver_key_size);
		}
		// printf("weaver key: "); output_hex((unsigned char*)weaver_key, weaver_key_size); printf("\n");
		// Send the slot from the .weaver file, the computed weaver key, and get the escrowed key data
		std::vector<uint8_t> weaver_payload;
		// TODO: we should return more information about the status including time delays before the next retry
		if (!weaver.WeaverVerify(wd.slot, weaver_key, &weaver_payload)) {
			printf("failed to weaver verify\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		// printf("weaver payload: "); output_hex(&weaver_payload); printf("\n");
		// Done with weaverVerify
		// Now we will compute the application ID
		// https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#964
		// Called from https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#780
		// The escrowed weaver key data is prefixed with "weaver-pwd" padded to 128 with nulls with the weaver payload appended then SHA512
		void* weaver_secret = PersonalizedHashBinary(PERSONALISATION_WEAVER_PASSWORD, (const char*)weaver_payload.data(), weaver_payload.size());
		// printf("weaver secret: "); output_hex((unsigned char*)weaver_secret, SHA512_DIGEST_LENGTH); printf("\n");
		// The application ID is the password token and weaver secret appended to each other
		memcpy((void*)&application_id[0], (void*)&password_token[0], PASSWORD_TOKEN_SIZE);
		memcpy((void*)&application_id[PASSWORD_TOKEN_SIZE], weaver_secret, SHA512_DIGEST_LENGTH);
		// printf("application ID: "); output_hex((unsigned char*)application_id, PASSWORD_TOKEN_SIZE + SHA512_DIGEST_LENGTH); printf("\n");
		// END PIXEL 2 WEAVER
	} else {
		printf("using secdis to decrypt spblob\n");
		std::string secdis_data;
		if (!Get_Secdis(spblob_path, handle_str, secdis_data)) {
			printf("Failed to get secdis data\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		void* secdiscardable = PersonalizedHashBinary(PERSONALISATION_SECDISCARDABLE, (char*)secdis_data.data(), secdis_data.size());
		if (!secdiscardable) {
			printf("malloc error getting secdiscardable\n");
			return Free_Return(retval, weaver_key, &pwd);
		}
		memcpy((void*)&application_id[0], (void*)&password_token[0], PASSWORD_TOKEN_SIZE);
		memcpy((void*)&application_id[PASSWORD_TOKEN_SIZE], secdiscardable, SHA512_DIGEST_LENGTH);
		if (Password != "!") {
			int ret = -1;
			bool request_reenroll = false;
			android::sp<android::hardware::gatekeeper::V1_0::IGatekeeper> gk_device;
			gk_device = ::android::hardware::gatekeeper::V1_0::IGatekeeper::getService();
			if (gk_device == nullptr) {
				printf("failed to get gatekeeper service\n");
				return Free_Return(retval, weaver_key, &pwd);
			}
			if (pwd.handle_len <= 0) {
				printf("no password handle supplied\n");
				return Free_Return(retval, weaver_key, &pwd);
			}
			android::hardware::hidl_vec<uint8_t> pwd_handle_hidl;
			pwd_handle_hidl.setToExternal(const_cast<uint8_t *>((const uint8_t *)pwd.password_handle), pwd.handle_len);
			void* gk_pwd_token = PersonalizedHashBinary(PERSONALIZATION_USER_GK_AUTH, (char*)&password_token[0], PASSWORD_TOKEN_SIZE);
			if (!gk_pwd_token) {
				printf("malloc error getting gatekeeper_key\n");
				return Free_Return(retval, weaver_key, &pwd);
			}
			android::hardware::hidl_vec<uint8_t> gk_pwd_token_hidl;
			gk_pwd_token_hidl.setToExternal(const_cast<uint8_t *>((const uint8_t *)gk_pwd_token), SHA512_DIGEST_LENGTH);

			// Android 10: Use file-based auth token approach
			// The keystore refuses root user to supply auth tokens directly,
			// so we write the auth token to a file and use keystore_auth service
			android::hardware::Return<void> hwRet =
				gk_device->verify(fakeUid(user_id), 0 /* challenge */,
								  pwd_handle_hidl,
								  gk_pwd_token_hidl,
								  [&ret, &request_reenroll, &auth_token_len]
									(const android::hardware::gatekeeper::V1_0::GatekeeperResponse &rsp) {
										ret = static_cast<int>(rsp.code);
										if (rsp.code >= android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::STATUS_OK) {
											auth_token_len = rsp.data.size();
											request_reenroll = (rsp.code == android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::STATUS_REENROLL);
											ret = 0;
											// Write auth token to file for keystore_auth service
											unlink("/auth_token");
											FILE* auth_file = fopen("/auth_token", "wb");
											if (auth_file != NULL) {
												fwrite(rsp.data.data(), sizeof(uint8_t), rsp.data.size(), auth_file);
												fclose(auth_file);
												printf("[SECDIS] Auth token written to /auth_token (%zu bytes)\n", rsp.data.size());
											} else {
												printf("[SECDIS] failed to open /auth_token for writing\n");
												ret = -2;
											}
										} else if (rsp.code == android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::ERROR_RETRY_TIMEOUT && rsp.timeout > 0) {
											ret = rsp.timeout;
										}
									}
								 );
			free(gk_pwd_token);
			if (!hwRet.isOk() || ret != 0) {
				printf("gatekeeper verification failed (ret=%d)\n", ret);
				return Free_Return(retval, weaver_key, &pwd);
			}
			printf("[SECDIS] Gatekeeper verification succeeded\n");
		}
	}
	// Now we will handle https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#816
	// Plus we will include the last bit that computes the disk decrypt key found in:
	// https://android.googlesource.com/platform/frameworks/base/+/android-8.0.0_r23/services/core/java/com/android/server/locksettings/SyntheticPasswordManager.java#153
	secret = android::keystore::unwrapSyntheticPasswordBlob(spblob_path, handle_str, user_id, (const void*)&application_id[0], 
		PASSWORD_TOKEN_SIZE + SHA512_DIGEST_LENGTH, auth_token_len);
	if (!secret.size()) {
		printf("failed to unwrapSyntheticPasswordBlob\n");
		return Free_Return(retval, weaver_key, &pwd);
	}

	if (!Decrypt_CE_storage(user_id, token, secret)) {
		return Free_Return(retval, weaver_key, &pwd);
	}

	retval = true;
	return Free_Return(retval, weaver_key, &pwd);
}

extern "C" int Get_Password_Type(const userid_t user_id, std::string& filename) {
	struct stat st;
	char spblob_path_char[PATH_MAX];
	sprintf(spblob_path_char, "/data/system_de/%d/spblob/", user_id);
	if (stat(spblob_path_char, &st) == 0) {
		std::string spblob_path = spblob_path_char;
		KeystoreInfo keystore_info;
		std::string handle_str = keystore_info.getHandle(user_id);
		printf("Handle is '%s'\n", handle_str.c_str());
		password_data_struct pwd;
		if (!Get_Password_Data(spblob_path, handle_str, &pwd)) {
			printf("Failed to Get_Password_Data\n");
			return 0;
		}
		// In Android type 1 is pattern
		// In Android <11 type 2 is PIN or password
		// In Android 11+ type 3 is PIN and type 4 is password
		if (pwd.password_type == 2) {
			printf("password type: password/PIN\n");
			return 1; // In TWRP this means password or PIN (Android <11)
		} else if (pwd.password_type == 4) {
			printf("password type: password\n");
			return 1; // In TWRP this means password
		} else if (pwd.password_type == 1) {
			printf("password type: pattern\n");
			return 2; // In TWRP this means pattern
		} else if (pwd.password_type == 3) {
			printf("password type: PIN\n");
			return 3; // In TWRP this means PIN
		}
		printf("using default password\n");
		return 0; // We'll try the default password
	}
	std::string path;
    if (user_id == 0) {
		path = "/data/system/";
	} else {
		char user_id_str[5];
		sprintf(user_id_str, "%i", user_id);	
		path = "/data/system/users/";
		path += user_id_str;
		path += "/";
	}
	filename = path + "gatekeeper.password.key";
	if (stat(filename.c_str(), &st) == 0 && st.st_size > 0)
		return 1;
	filename = path + "gatekeeper.pattern.key";
	if (stat(filename.c_str(), &st) == 0 && st.st_size > 0)
		return 2;
	printf("Unable to locate gatekeeper password file '%s'\n", filename.c_str());
	filename = "";
	return 0;
}

extern "C" bool Decrypt_User(const userid_t user_id, const std::string& Password) {
	printf("[DEBUG] Decrypt_User: ENTER user_id=%d\n", user_id);
	printf("Attempting to decrypt user\n");
    uint8_t *auth_token;
    uint32_t auth_token_len;
    int ret;

    struct stat st;
    if (user_id > 9999) {
		printf("user_id is too big\n");
		return false;
	}
    std::string filename;
    bool Default_Password = (Password == "!");
    if (Get_Password_Type(user_id, filename) == 0 && !Default_Password) {
		printf("Unknown password type\n");
		return false;
	}

	if (Default_Password) {
		if (!Decrypt_CE_storage(user_id, 0, "!")) {
			return Decrypt_User_Synth_Pass(user_id, Password);
		}
		return true;
	}
	if (stat("/data/system_de/0/spblob", &st) == 0) {
		printf("Using synthetic password method\n");
		return Decrypt_User_Synth_Pass(user_id, Password);
	}
	// printf("password filename is '%s'\n", filename.c_str());
	if (stat(filename.c_str(), &st) != 0) {
		printf("error stat'ing key file: %s\n", strerror(errno));
		return false;
	}
	std::string handle;
    if (!android::base::ReadFileToString(filename, &handle)) {
		printf("Failed to read '%s'\n", filename.c_str());
		return false;
	}
    bool should_reenroll;
	bool request_reenroll = false;
	android::sp<android::hardware::gatekeeper::V1_0::IGatekeeper> gk_device;
	gk_device = ::android::hardware::gatekeeper::V1_0::IGatekeeper::getService();
	if (gk_device == nullptr)
		return false;
	android::hardware::hidl_vec<uint8_t> curPwdHandle;
	curPwdHandle.setToExternal(const_cast<uint8_t *>((const uint8_t *)handle.c_str()), st.st_size);
	android::hardware::hidl_vec<uint8_t> enteredPwd;
	enteredPwd.setToExternal(const_cast<uint8_t *>((const uint8_t *)Password.c_str()), Password.size());

	android::hardware::Return<void> hwRet =
		gk_device->verify(user_id, 0 /* challange */,
						  curPwdHandle,
						  enteredPwd,
						  [&ret, &request_reenroll, &auth_token, &auth_token_len]
							(const android::hardware::gatekeeper::V1_0::GatekeeperResponse &rsp) {
								ret = static_cast<int>(rsp.code); // propagate errors
								if (rsp.code >= android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::STATUS_OK) {
									auth_token = new uint8_t[rsp.data.size()];
									auth_token_len = rsp.data.size();
									memcpy(auth_token, rsp.data.data(), auth_token_len);
									request_reenroll = (rsp.code == android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::STATUS_REENROLL);
									ret = 0; // all success states are reported as 0
								} else if (rsp.code == android::hardware::gatekeeper::V1_0::GatekeeperStatusCode::ERROR_RETRY_TIMEOUT && rsp.timeout > 0) {
									ret = rsp.timeout;
								}
							}
						 );
	if (!hwRet.isOk()) {
		return false;
	}

	char token_hex[(auth_token_len*2)+1];
	token_hex[(auth_token_len*2)] = 0;
	uint32_t i;
	for (i=0;i<auth_token_len;i++) {
		sprintf(&token_hex[2*i], "%02X", auth_token[i]);
	}
	// The secret is "Android FBE credential hash" plus appended 0x00 to reach 128 bytes then append the user's password then feed that to sha512sum
	std::string secret = HashPassword(Password);
	if (!Decrypt_CE_storage(user_id, 0, secret)) {
		return false;
	}
	return true;
}
}  // namespace keystore
}  // namespace android
