/*
 * Copyright (C) 2016 The Android Open Source Project
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

// Hybrid Keymaster implementation for TWRP
// Uses raw HIDL Keymaster V4.0 interface directly (no wrapper with CHECK macros)
// Modified for Vivo Y73S (PD2031)

#include "Keymaster.h"

#include <android-base/logging.h>
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <keymasterV4_1/authorization_set.h>
#include <keymasterV4_1/keymaster_utils.h>

namespace android {
namespace vold {

using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using IKeymasterDevice40 = ::android::hardware::keymaster::V4_0::IKeymasterDevice;

// Static member initialization
/* static */ bool Keymaster::hmacKeyGenerated = false;

// ============================================================================
// Type Conversion Functions
// ============================================================================

/* static */ km_hidl::ErrorCode Keymaster::convertErrorToHidl(km::ErrorCode error) {
    return static_cast<km_hidl::ErrorCode>(static_cast<int32_t>(error));
}

/* static */ km::ErrorCode Keymaster::convertErrorFromHidl(km_hidl::ErrorCode error) {
    return static_cast<km::ErrorCode>(static_cast<int32_t>(error));
}

/* static */ km_hidl::AuthorizationSet Keymaster::convertToHidl(
        const km::AuthorizationSet& keymintParams) {
    km_hidl::AuthorizationSet hidlParams;
    LOG(DEBUG) << "[Keymaster] convertToHidl: Converting " << keymintParams.size() << " parameters";

    for (const auto& param : keymintParams) {
        km_hidl::KeyParameter hidlParam;
        hidlParam.tag = static_cast<km_hidl::Tag>(static_cast<int32_t>(param.tag));

        // Get the tag type from the high bits (bits 28-31)
        auto tagType = static_cast<uint32_t>(param.tag) & (0xF << 28);
        LOG(DEBUG) << "[Keymaster] convertToHidl: tag=" << static_cast<int32_t>(param.tag)
                   << " tagType=0x" << std::hex << tagType;

        switch (tagType) {
            case static_cast<uint32_t>(km_hidl::TagType::ENUM):
            case static_cast<uint32_t>(km_hidl::TagType::ENUM_REP):
                // Handle enum types - keymint uses specific enum types, but we need integer
                switch (param.tag) {
                    case km::Tag::PURPOSE:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::keyPurpose>());
                        break;
                    case km::Tag::ALGORITHM:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::algorithm>());
                        break;
                    case km::Tag::BLOCK_MODE:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::blockMode>());
                        break;
                    case km::Tag::DIGEST:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::digest>());
                        break;
                    case km::Tag::PADDING:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::paddingMode>());
                        break;
                    case km::Tag::EC_CURVE:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::ecCurve>());
                        break;
                    case km::Tag::ORIGIN:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::origin>());
                        break;
                    case km::Tag::USER_AUTH_TYPE:
                        hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::hardwareAuthenticatorType>());
                        break;
                    default:
                        // Skip unknown enum tags - can't safely access without knowing type
                        LOG(WARNING) << "[Keymaster] convertToHidl: Unknown enum tag " << static_cast<int32_t>(param.tag);
                        continue;
                }
                break;
            case static_cast<uint32_t>(km_hidl::TagType::UINT):
            case static_cast<uint32_t>(km_hidl::TagType::UINT_REP):
                hidlParam.f.integer = static_cast<uint32_t>(param.value.get<km::KeyParameterValue::integer>());
                break;
            case static_cast<uint32_t>(km_hidl::TagType::ULONG):
            case static_cast<uint32_t>(km_hidl::TagType::ULONG_REP):
                hidlParam.f.longInteger = static_cast<uint64_t>(param.value.get<km::KeyParameterValue::longInteger>());
                break;
            case static_cast<uint32_t>(km_hidl::TagType::DATE):
                hidlParam.f.dateTime = static_cast<uint64_t>(param.value.get<km::KeyParameterValue::dateTime>());
                break;
            case static_cast<uint32_t>(km_hidl::TagType::BOOL):
                // Bool tags don't need value extraction - presence means true
                break;
            case static_cast<uint32_t>(km_hidl::TagType::BYTES): {
                const auto& blob = param.value.get<km::KeyParameterValue::blob>();
                hidlParam.blob.setToExternal(const_cast<uint8_t*>(blob.data()), blob.size());
                break;
            }
            default:
                LOG(WARNING) << "[Keymaster] convertToHidl: Unknown tag type 0x" << std::hex << tagType
                             << " for tag " << std::dec << static_cast<int32_t>(param.tag);
                continue;
        }
        hidlParams.push_back(hidlParam);
    }
    return hidlParams;
}

/* static */ km::AuthorizationSet Keymaster::convertFromHidl(
        const km_hidl::AuthorizationSet& hidlParams) {
    km::AuthorizationSet keymintParams;
    for (const auto& param : hidlParams) {
        km::KeyParameter keymintParam;
        keymintParam.tag = static_cast<km::Tag>(static_cast<int32_t>(param.tag));
        auto tagType = static_cast<uint32_t>(param.tag) & (0xF << 28);
        switch (tagType) {
            case static_cast<uint32_t>(km_hidl::TagType::ENUM):
            case static_cast<uint32_t>(km_hidl::TagType::ENUM_REP):
            case static_cast<uint32_t>(km_hidl::TagType::UINT):
            case static_cast<uint32_t>(km_hidl::TagType::UINT_REP):
                keymintParam.value = km::KeyParameterValue::make<km::KeyParameterValue::integer>(
                    static_cast<int32_t>(param.f.integer));
                break;
            case static_cast<uint32_t>(km_hidl::TagType::ULONG):
            case static_cast<uint32_t>(km_hidl::TagType::ULONG_REP):
                keymintParam.value = km::KeyParameterValue::make<km::KeyParameterValue::longInteger>(
                    static_cast<int64_t>(param.f.longInteger));
                break;
            case static_cast<uint32_t>(km_hidl::TagType::DATE):
                keymintParam.value = km::KeyParameterValue::make<km::KeyParameterValue::dateTime>(
                    static_cast<int64_t>(param.f.dateTime));
                break;
            case static_cast<uint32_t>(km_hidl::TagType::BOOL):
                keymintParam.value = km::KeyParameterValue::make<km::KeyParameterValue::boolValue>(true);
                break;
            case static_cast<uint32_t>(km_hidl::TagType::BYTES):
                keymintParam.value = km::KeyParameterValue::make<km::KeyParameterValue::blob>(
                    std::vector<uint8_t>(param.blob.begin(), param.blob.end()));
                break;
            default:
                continue;
        }
        keymintParams.push_back(keymintParam);
    }
    return keymintParams;
}

/* static */ std::optional<km_hidl::KeyPurpose> Keymaster::extractPurpose(
        const km::AuthorizationSet& params) {
    for (const auto& param : params) {
        if (param.tag == km::Tag::PURPOSE) {
            return static_cast<km_hidl::KeyPurpose>(param.value.get<km::KeyParameterValue::keyPurpose>());
        }
    }
    return std::nullopt;
}

// ============================================================================
// KeymasterOperation Implementation - Uses raw IKeymasterDevice40
// ============================================================================

KeymasterOperation::~KeymasterOperation() {
    if (mDevice) {
        LOG(DEBUG) << "[Keymaster] ~KeymasterOperation: Aborting operation";
        mDevice->abort(mOpHandle);
    }
}

bool KeymasterOperation::updateCompletely(const char* input, size_t inputLen,
                                          const std::function<void(const char*, size_t)> consumer) {
    LOG(DEBUG) << "[Keymaster] updateCompletely: Processing " << inputLen << " bytes";
    uint32_t inputConsumed = 0;
    km_hidl::ErrorCode km_error;

    auto hidlCB = [&](km_hidl::ErrorCode ret, uint32_t inputConsumedDelta,
                      const hidl_vec<km_hidl::KeyParameter>&,
                      const hidl_vec<uint8_t>& _output) {
        km_error = ret;
        if (km_error != km_hidl::ErrorCode::OK) return;
        inputConsumed += inputConsumedDelta;
        if (_output.size() > 0) consumer(reinterpret_cast<const char*>(&_output[0]), _output.size());
    };

    while (inputConsumed != inputLen) {
        size_t toRead = inputLen - inputConsumed;
        auto inputBlob = km_hidl::support::blob2hidlVec(
            reinterpret_cast<const uint8_t*>(&input[inputConsumed]), toRead);
        auto error = mDevice->update(mOpHandle, hidl_vec<km_hidl::KeyParameter>(), inputBlob,
                                     km_hidl::HardwareAuthToken(), km_hidl::VerificationToken(), hidlCB);
        if (!error.isOk()) {
            LOG(ERROR) << "[Keymaster] updateCompletely: HIDL error: " << error.description();
            mDevice = nullptr;
            return false;
        }
        if (km_error != km_hidl::ErrorCode::OK) {
            LOG(ERROR) << "[Keymaster] updateCompletely: Error " << int32_t(km_error);
            mDevice = nullptr;
            mError = Keymaster::convertErrorFromHidl(km_error);
            return false;
        }
        if (inputConsumed > inputLen) {
            mDevice = nullptr;
            return false;
        }
    }
    return true;
}

bool KeymasterOperation::finish(std::string* output) {
    LOG(DEBUG) << "[Keymaster] finish: Finalizing operation";
    km_hidl::ErrorCode km_error;
    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<km_hidl::KeyParameter>&,
                      const hidl_vec<uint8_t>& _output) {
        km_error = ret;
        if (km_error != km_hidl::ErrorCode::OK) return;
        if (output && _output.size() > 0)
            output->assign(reinterpret_cast<const char*>(&_output[0]), _output.size());
    };
    auto error = mDevice->finish(mOpHandle, hidl_vec<km_hidl::KeyParameter>(), hidl_vec<uint8_t>(),
                                 hidl_vec<uint8_t>(), km_hidl::HardwareAuthToken(),
                                 km_hidl::VerificationToken(), hidlCb);
    mDevice = nullptr;
    if (!error.isOk()) {
        LOG(ERROR) << "[Keymaster] finish: HIDL error: " << error.description();
        return false;
    }
    if (km_error != km_hidl::ErrorCode::OK) {
        LOG(ERROR) << "[Keymaster] finish: Error " << int32_t(km_error);
        mError = Keymaster::convertErrorFromHidl(km_error);
        return false;
    }
    return true;
}

// ============================================================================
// Keymaster Implementation - Direct IKeymasterDevice40 usage (no wrapper)
// ============================================================================

Keymaster::Keymaster() {
    printf("[Keymaster] Constructor: Initializing...\n");
    LOG(INFO) << "[Keymaster] Initializing Keymaster (Raw HIDL interface)";

    // Try to get Trustonic keymaster first (Vivo Y73S uses Trustonic TEE)
    printf("[Keymaster] Constructor: Trying trustonic service...\n");
    LOG(INFO) << "[Keymaster] Trying trustonic keymaster service...";
    mDevice = IKeymasterDevice40::getService("trustonic");
    if (mDevice) {
        printf("[Keymaster] Constructor: Found trustonic keymaster 4.0\n");
        LOG(INFO) << "[Keymaster] Found trustonic keymaster 4.0 service";

        // Get hardware info (no CHECK, just log)
        bool gotInfo = false;
        auto rc = mDevice->getHardwareInfo([&](km_hidl::SecurityLevel securityLevel,
                                               const hidl_string& keymasterName,
                                               const hidl_string& authorName) {
            printf("[Keymaster] Constructor: Device=%s, Author=%s, SecurityLevel=%d\n",
                   keymasterName.c_str(), authorName.c_str(), static_cast<int32_t>(securityLevel));
            LOG(INFO) << "[Keymaster] Device: " << keymasterName.c_str()
                      << " from " << authorName.c_str()
                      << ", Security level: " << static_cast<int32_t>(securityLevel);
            mSecurityLevel = securityLevel;
            gotInfo = true;
        });
        if (!rc.isOk()) {
            printf("[Keymaster] Constructor: getHardwareInfo failed\n");
            LOG(WARNING) << "[Keymaster] getHardwareInfo failed: " << rc.description();
        }

        // Perform HMAC key agreement (safe version)
        if (!hmacKeyGenerated) {
            printf("[Keymaster] Constructor: Performing HMAC agreement...\n");
            safePerformHmacKeyAgreement();
        } else {
            printf("[Keymaster] Constructor: HMAC already done\n");
        }
        return;
    }

    // Try default keymaster 4.0
    printf("[Keymaster] Constructor: Trying default service...\n");
    LOG(INFO) << "[Keymaster] Trying default keymaster 4.0 service...";
    mDevice = IKeymasterDevice40::getService("default");
    if (mDevice) {
        printf("[Keymaster] Constructor: Found default keymaster 4.0\n");
        LOG(INFO) << "[Keymaster] Found default keymaster 4.0 service";

        bool gotInfo = false;
        auto rc = mDevice->getHardwareInfo([&](km_hidl::SecurityLevel securityLevel,
                                               const hidl_string& keymasterName,
                                               const hidl_string& authorName) {
            printf("[Keymaster] Constructor: Device=%s, Author=%s, SecurityLevel=%d\n",
                   keymasterName.c_str(), authorName.c_str(), static_cast<int32_t>(securityLevel));
            LOG(INFO) << "[Keymaster] Device: " << keymasterName.c_str()
                      << " from " << authorName.c_str()
                      << ", Security level: " << static_cast<int32_t>(securityLevel);
            mSecurityLevel = securityLevel;
            gotInfo = true;
        });
        if (!rc.isOk()) {
            printf("[Keymaster] Constructor: getHardwareInfo failed\n");
            LOG(WARNING) << "[Keymaster] getHardwareInfo failed: " << rc.description();
        }

        if (!hmacKeyGenerated) {
            safePerformHmacKeyAgreement();
        }
        return;
    }

    LOG(ERROR) << "[Keymaster] No keymaster devices found!";
}

void Keymaster::safePerformHmacKeyAgreement() {
    if (!mDevice) return;

    printf("[Keymaster] HMAC: Getting parameters...\n");
    LOG(INFO) << "[Keymaster] HMAC agreement: Getting parameters...";

    km_hidl::HmacSharingParameters myParams;
    bool gotParams = false;
    km_hidl::ErrorCode paramError = km_hidl::ErrorCode::UNKNOWN_ERROR;

    auto rc = mDevice->getHmacSharingParameters([&](auto error, auto& params) {
        paramError = error;
        printf("[Keymaster] HMAC: getHmacSharingParameters callback error=%d\n", static_cast<int32_t>(error));
        if (error == km_hidl::ErrorCode::OK) {
            myParams = params;
            gotParams = true;
        }
    });

    if (!rc.isOk()) {
        printf("[Keymaster] HMAC: getHmacSharingParameters HIDL error\n");
        LOG(WARNING) << "[Keymaster] HMAC: getHmacSharingParameters HIDL error: " << rc.description();
        return;
    }

    if (!gotParams) {
        printf("[Keymaster] HMAC: getHmacSharingParameters failed error=%d\n", static_cast<int32_t>(paramError));
        LOG(WARNING) << "[Keymaster] HMAC: getHmacSharingParameters error: " << static_cast<int32_t>(paramError);
        return;
    }

    printf("[Keymaster] HMAC: Got parameters, computing HMAC...\n");
    LOG(INFO) << "[Keymaster] HMAC: Got parameters, computing HMAC...";

    hidl_vec<km_hidl::HmacSharingParameters> allParams;
    allParams.resize(1);
    allParams[0] = myParams;

    km_hidl::ErrorCode hmacError = km_hidl::ErrorCode::UNKNOWN_ERROR;
    bool hmacOk = false;

    rc = mDevice->computeSharedHmac(allParams, [&](auto error, auto& sharingCheck) {
        hmacError = error;
        printf("[Keymaster] HMAC: computeSharedHmac callback error=%d, checkSize=%zu\n",
               static_cast<int32_t>(error), sharingCheck.size());
        if (error == km_hidl::ErrorCode::OK) {
            hmacOk = true;
            LOG(INFO) << "[Keymaster] HMAC: Success, sharingCheck size = " << sharingCheck.size();
        }
    });

    if (!rc.isOk()) {
        printf("[Keymaster] HMAC: computeSharedHmac HIDL error\n");
        LOG(WARNING) << "[Keymaster] HMAC: computeSharedHmac HIDL error: " << rc.description();
        return;
    }

    if (!hmacOk) {
        printf("[Keymaster] HMAC: computeSharedHmac failed error=%d\n", static_cast<int32_t>(hmacError));
        LOG(WARNING) << "[Keymaster] HMAC: computeSharedHmac error: " << static_cast<int32_t>(hmacError);
        return;
    }

    hmacKeyGenerated = true;
    printf("[Keymaster] HMAC: SUCCESS\n");
    LOG(INFO) << "[Keymaster] HMAC: Completed successfully";
}

bool Keymaster::generateKey(const km::AuthorizationSet& inParams, std::string* key) {
    LOG(INFO) << "[Keymaster] generateKey: Generating new key";
    if (!mDevice) {
        LOG(ERROR) << "[Keymaster] generateKey: No device";
        return false;
    }

    auto hidlParams = convertToHidl(inParams);
    km_hidl::ErrorCode km_error;
    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<uint8_t>& keyBlob,
                      const km_hidl::KeyCharacteristics&) {
        km_error = ret;
        if (km_error != km_hidl::ErrorCode::OK) return;
        if (key && keyBlob.size() > 0)
            key->assign(reinterpret_cast<const char*>(&keyBlob[0]), keyBlob.size());
    };

    auto error = mDevice->generateKey(hidlParams.hidl_data(), hidlCb);
    if (!error.isOk()) {
        LOG(ERROR) << "[Keymaster] generateKey: HIDL error: " << error.description();
        return false;
    }
    if (km_error != km_hidl::ErrorCode::OK) {
        LOG(ERROR) << "[Keymaster] generateKey: Error " << int32_t(km_error);
        return false;
    }
    LOG(INFO) << "[Keymaster] generateKey: Success";
    return true;
}

bool Keymaster::exportKey(const KeyBuffer& kmKey, std::string* key) {
    LOG(INFO) << "[Keymaster] exportKey: Attempting export";
    if (!mDevice) {
        LOG(ERROR) << "[Keymaster] exportKey: No device";
        return false;
    }

    auto keyBlob = km_hidl::support::blob2hidlVec(
        reinterpret_cast<const uint8_t*>(kmKey.data()), kmKey.size());

    km_hidl::ErrorCode km_error;
    std::string exportedKey;
    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<uint8_t>& exportData) {
        km_error = ret;
        if (km_error != km_hidl::ErrorCode::OK) return;
        if (exportData.size() > 0)
            exportedKey.assign(reinterpret_cast<const char*>(&exportData[0]), exportData.size());
    };

    auto error = mDevice->exportKey(km_hidl::KeyFormat::RAW, keyBlob,
                                    hidl_vec<uint8_t>(), hidl_vec<uint8_t>(), hidlCb);
    if (!error.isOk() || km_error != km_hidl::ErrorCode::OK) {
        LOG(WARNING) << "[Keymaster] exportKey: Using key directly";
        if (key) key->assign(kmKey.begin(), kmKey.end());
        return true;
    }
    if (key) *key = exportedKey;
    LOG(INFO) << "[Keymaster] exportKey: Success";
    return true;
}

bool Keymaster::deleteKey(const std::string& key) {
    LOG(INFO) << "[Keymaster] deleteKey";
    if (!mDevice) return false;
    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto error = mDevice->deleteKey(keyBlob);
    if (!error.isOk()) {
        LOG(ERROR) << "[Keymaster] deleteKey: HIDL error";
        return false;
    }
    return true;
}

bool Keymaster::upgradeKey(const std::string& oldKey, const km::AuthorizationSet& inParams,
                           std::string* newKey) {
    printf("[Keymaster] upgradeKey: ENTER oldKeySize=%zu\n", oldKey.size());
    LOG(INFO) << "[Keymaster] upgradeKey";
    if (!mDevice) {
        printf("[Keymaster] upgradeKey: No device\n");
        return false;
    }

    auto oldKeyBlob = km_hidl::support::blob2hidlVec(oldKey);
    auto hidlParams = convertToHidl(inParams);
    printf("[Keymaster] upgradeKey: hidlParams count=%zu\n", hidlParams.size());
    km_hidl::ErrorCode km_error = km_hidl::ErrorCode::UNKNOWN_ERROR;
    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<uint8_t>& upgradedKeyBlob) {
        km_error = ret;
        printf("[Keymaster] upgradeKey callback: error=%d, newKeySize=%zu\n",
               static_cast<int32_t>(ret), upgradedKeyBlob.size());
        if (km_error != km_hidl::ErrorCode::OK) return;
        if (newKey && upgradedKeyBlob.size() > 0)
            newKey->assign(reinterpret_cast<const char*>(&upgradedKeyBlob[0]), upgradedKeyBlob.size());
    };

    printf("[Keymaster] upgradeKey: calling mDevice->upgradeKey()...\n");
    auto error = mDevice->upgradeKey(oldKeyBlob, hidlParams.hidl_data(), hidlCb);
    printf("[Keymaster] upgradeKey: mDevice->upgradeKey() returned, isOk=%d\n", error.isOk());
    if (!error.isOk()) {
        printf("[Keymaster] upgradeKey: HIDL transport error\n");
        LOG(ERROR) << "[Keymaster] upgradeKey: HIDL error";
        return false;
    }
    if (km_error != km_hidl::ErrorCode::OK) {
        printf("[Keymaster] upgradeKey: FAILED error=%d\n", static_cast<int32_t>(km_error));
        LOG(ERROR) << "[Keymaster] upgradeKey: Error " << int32_t(km_error);
        return false;
    }
    printf("[Keymaster] upgradeKey: SUCCESS newKeySize=%zu\n", newKey ? newKey->size() : 0);
    return true;
}

bool Keymaster::getKeyCharacteristics(const std::string& key, km::AuthorizationSet* hwEnforced,
                                       km::AuthorizationSet* swEnforced) {
    printf("[Keymaster] getKeyCharacteristics: ENTER keySize=%zu\n", key.size());
    if (!mDevice) {
        printf("[Keymaster] getKeyCharacteristics: No device\n");
        return false;
    }

    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    hidl_vec<uint8_t> clientId, appData;  // empty for most keys

    km_hidl::ErrorCode km_error = km_hidl::ErrorCode::UNKNOWN_ERROR;
    km_hidl::KeyCharacteristics chars;

    auto hidlCb = [&](km_hidl::ErrorCode ret, const km_hidl::KeyCharacteristics& keyChars) {
        km_error = ret;
        printf("[Keymaster] getKeyCharacteristics callback: error=%d\n", static_cast<int32_t>(ret));
        if (km_error == km_hidl::ErrorCode::OK) {
            chars = keyChars;
        }
    };

    auto error = mDevice->getKeyCharacteristics(keyBlob, clientId, appData, hidlCb);
    if (!error.isOk()) {
        printf("[Keymaster] getKeyCharacteristics: HIDL transport error\n");
        return false;
    }
    if (km_error != km_hidl::ErrorCode::OK) {
        printf("[Keymaster] getKeyCharacteristics: FAILED error=%d\n", static_cast<int32_t>(km_error));
        return false;
    }

    // Print key characteristics for debugging
    printf("[Keymaster] Key characteristics:\n");
    printf("[Keymaster]   HW enforced params: %zu\n", chars.hardwareEnforced.size());
    for (const auto& param : chars.hardwareEnforced) {
        printf("[Keymaster]     tag=%u\n", static_cast<uint32_t>(param.tag));
    }
    printf("[Keymaster]   SW enforced params: %zu\n", chars.softwareEnforced.size());
    for (const auto& param : chars.softwareEnforced) {
        printf("[Keymaster]     tag=%u\n", static_cast<uint32_t>(param.tag));
    }

    if (hwEnforced) *hwEnforced = convertFromHidl(chars.hardwareEnforced);
    if (swEnforced) *swEnforced = convertFromHidl(chars.softwareEnforced);

    printf("[Keymaster] getKeyCharacteristics: SUCCESS\n");
    return true;
}

KeymasterOperation Keymaster::begin(const std::string& key, const km::AuthorizationSet& inParams,
                                    km::AuthorizationSet* outParams) {
    LOG(INFO) << "[Keymaster] begin: Starting crypto operation";
    if (!mDevice) {
        printf("[Keymaster] begin: No device\n");
        LOG(ERROR) << "[Keymaster] begin: No device";
        return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
    }

    auto purposeOpt = extractPurpose(inParams);
    km_hidl::KeyPurpose purpose = purposeOpt.value_or(km_hidl::KeyPurpose::ENCRYPT);
    printf("[Keymaster] begin: Purpose=%d, keySize=%zu, paramsCount=%zu\n",
           static_cast<int32_t>(purpose), key.size(), inParams.size());
    LOG(DEBUG) << "[Keymaster] begin: Purpose = " << static_cast<int32_t>(purpose);

    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto hidlParams = convertToHidl(inParams);
    printf("[Keymaster] begin: hidlParams count=%zu\n", hidlParams.size());

    uint64_t mOpHandle = 0;
    km_hidl::ErrorCode km_error = km_hidl::ErrorCode::UNKNOWN_ERROR;
    km_hidl::AuthorizationSet hidlOutParams;

    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<km_hidl::KeyParameter>& _outParams,
                      uint64_t operationHandle) {
        km_error = ret;
        printf("[Keymaster] begin callback: error=%d, handle=%llu\n", static_cast<int32_t>(ret), (unsigned long long)operationHandle);
        if (km_error != km_hidl::ErrorCode::OK) return;
        hidlOutParams = _outParams;
        mOpHandle = operationHandle;
    };

    printf("[Keymaster] begin: calling mDevice->begin()...\n");
    auto error = mDevice->begin(purpose, keyBlob, hidlParams.hidl_data(),
                                km_hidl::HardwareAuthToken(), hidlCb);
    printf("[Keymaster] begin: mDevice->begin() returned, isOk=%d\n", error.isOk());
    if (!error.isOk()) {
        printf("[Keymaster] begin: HIDL transport error: %s\n", error.description().c_str());
        LOG(ERROR) << "[Keymaster] begin: HIDL error: " << error.description();
        return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
    }

    printf("[Keymaster] begin: km_error=%d\n", static_cast<int32_t>(km_error));
    if (km_error == km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE) {
        printf("[Keymaster] begin: Key requires upgrade, attempting...\n");
        LOG(INFO) << "[Keymaster] begin: Key requires upgrade";
        std::string upgradedKey;
        // upgradeKey needs empty params - keymaster will use current OS_VERSION/OS_PATCHLEVEL
        km::AuthorizationSet emptyParams;
        if (upgradeKey(key, emptyParams, &upgradedKey)) {
            printf("[Keymaster] begin: upgradeKey succeeded, retrying begin with upgraded key\n");
            auto upgradedKeyBlob = km_hidl::support::blob2hidlVec(upgradedKey);
            error = mDevice->begin(purpose, upgradedKeyBlob, hidlParams.hidl_data(),
                                   km_hidl::HardwareAuthToken(), hidlCb);
            if (error.isOk() && km_error == km_hidl::ErrorCode::OK) {
                printf("[Keymaster] begin: Success with upgraded key\n");
                LOG(INFO) << "[Keymaster] begin: Success with upgraded key";
                if (outParams) *outParams = convertFromHidl(hidlOutParams);
                return KeymasterOperation(mDevice.get(), mOpHandle, upgradedKey);
            }
            printf("[Keymaster] begin: begin with upgraded key failed, error=%d\n", static_cast<int32_t>(km_error));
        }
    }

    if (km_error != km_hidl::ErrorCode::OK) {
        printf("[Keymaster] begin: FAILED with error=%d\n", static_cast<int32_t>(km_error));
        LOG(ERROR) << "[Keymaster] begin: Error " << int32_t(km_error);
        return KeymasterOperation(Keymaster::convertErrorFromHidl(km_error));
    }

    if (outParams) *outParams = convertFromHidl(hidlOutParams);
    printf("[Keymaster] begin: SUCCESS handle=%llu\n", (unsigned long long)mOpHandle);
    LOG(INFO) << "[Keymaster] begin: Success, handle = " << mOpHandle;
    return KeymasterOperation(mDevice.get(), mOpHandle);
}

KeymasterOperation Keymaster::begin(const std::string& key, const km::AuthorizationSet& inParams,
                                    km::AuthorizationSet* outParams,
                                    const km_hidl::HardwareAuthToken& authToken) {
    LOG(INFO) << "[Keymaster] begin (with authToken): Starting crypto operation";
    if (!mDevice) {
        printf("[Keymaster] begin: No device\n");
        return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
    }

    auto purposeOpt = extractPurpose(inParams);
    km_hidl::KeyPurpose purpose = purposeOpt.value_or(km_hidl::KeyPurpose::ENCRYPT);
    printf("[Keymaster] begin (authToken): Purpose=%d, keySize=%zu, paramsCount=%zu\n",
           static_cast<int32_t>(purpose), key.size(), inParams.size());

    auto keyBlob = km_hidl::support::blob2hidlVec(key);
    auto hidlParams = convertToHidl(inParams);

    uint64_t mOpHandle = 0;
    km_hidl::ErrorCode km_error = km_hidl::ErrorCode::UNKNOWN_ERROR;
    km_hidl::AuthorizationSet hidlOutParams;

    auto hidlCb = [&](km_hidl::ErrorCode ret, const hidl_vec<km_hidl::KeyParameter>& _outParams,
                      uint64_t operationHandle) {
        km_error = ret;
        printf("[Keymaster] begin callback: error=%d, handle=%llu\n", static_cast<int32_t>(ret), (unsigned long long)operationHandle);
        if (km_error != km_hidl::ErrorCode::OK) return;
        mOpHandle = operationHandle;
        hidlOutParams = _outParams;
    };

    printf("[Keymaster] begin (authToken): calling mDevice->begin() with auth token...\n");
    auto error = mDevice->begin(purpose, keyBlob, hidlParams.hidl_data(), authToken, hidlCb);
    printf("[Keymaster] begin: mDevice->begin() returned, isOk=%d\n", error.isOk());

    if (!error.isOk()) {
        printf("[Keymaster] begin: HIDL transport error\n");
        return KeymasterOperation(km::ErrorCode::UNKNOWN_ERROR);
    }

    // Handle KEY_REQUIRES_UPGRADE
    if (km_error == km_hidl::ErrorCode::KEY_REQUIRES_UPGRADE) {
        printf("[Keymaster] begin: Key requires upgrade, attempting...\n");
        std::string upgradedKey;
        km::AuthorizationSet emptyParams;
        if (upgradeKey(key, emptyParams, &upgradedKey)) {
            printf("[Keymaster] begin: upgradeKey succeeded, retrying with upgraded key\n");
            auto upgradedKeyBlob = km_hidl::support::blob2hidlVec(upgradedKey);
            error = mDevice->begin(purpose, upgradedKeyBlob, hidlParams.hidl_data(), authToken, hidlCb);
            if (error.isOk() && km_error == km_hidl::ErrorCode::OK) {
                printf("[Keymaster] begin: Success with upgraded key\n");
                if (outParams) *outParams = convertFromHidl(hidlOutParams);
                return KeymasterOperation(mDevice.get(), mOpHandle, upgradedKey);
            }
        }
    }

    if (km_error != km_hidl::ErrorCode::OK) {
        printf("[Keymaster] begin: FAILED with error=%d\n", static_cast<int32_t>(km_error));
        return KeymasterOperation(Keymaster::convertErrorFromHidl(km_error));
    }

    if (outParams) *outParams = convertFromHidl(hidlOutParams);
    printf("[Keymaster] begin: SUCCESS handle=%llu\n", (unsigned long long)mOpHandle);
    return KeymasterOperation(mDevice.get(), mOpHandle);
}

bool Keymaster::isSecure() {
    if (!mDevice) return false;
    return mSecurityLevel != km_hidl::SecurityLevel::SOFTWARE;
}

/* static */ void Keymaster::earlyBootEnded() {
    LOG(INFO) << "[Keymaster] earlyBootEnded: no-op for HIDL V4.0";
}

/* static */ void Keymaster::deleteAllKeys() {
    LOG(INFO) << "[Keymaster] deleteAllKeys: not supported on HIDL V4.0";
}

}  // namespace vold
}  // namespace android
