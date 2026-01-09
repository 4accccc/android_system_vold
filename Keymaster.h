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
// Uses raw HIDL Keymaster V4.0 interface directly (no wrapper)
// Modified for Vivo Y73S (PD2031)

#ifndef ANDROID_VOLD_KEYMASTER_H
#define ANDROID_VOLD_KEYMASTER_H

#include "KeyBuffer.h"

#include <memory>
#include <string>
#include <utility>
#include <functional>
#include <optional>

#include <android-base/macros.h>

// HIDL Keymaster V4.0 headers
#include <android/hardware/keymaster/4.0/IKeymasterDevice.h>
#include <keymasterV4_1/authorization_set.h>

// Keymint support for TWRP compatibility
#include <keymint_support/authorization_set.h>
#include <keymint_support/keymint_tags.h>
#include <aidl/android/hardware/security/keymint/ErrorCode.h>

namespace android {
namespace vold {

// Use keymint namespace for TWRP compatibility (same as Android 12 interface)
namespace km = ::aidl::android::hardware::security::keymint;

// HIDL namespace alias for internal use
namespace km_hidl = ::android::hardware::keymaster::V4_0;

// Use raw IKeymasterDevice40 directly instead of support wrapper
using KmDevice = km_hidl::IKeymasterDevice;

// Wrapper for a Keymaster operation handle representing an
// ongoing Keymaster operation. Aborts the operation
// in the destructor if it is unfinished. Methods log failures
// to LOG(ERROR).
class KeymasterOperation {
  public:
    ~KeymasterOperation();

    // Is this instance valid? This is false if creation fails, and becomes
    // false on finish or if an update fails.
    explicit operator bool() const {
        return mError == km::ErrorCode::OK && mDevice != nullptr;
    }

    // Get error code (keymint style for TWRP compatibility)
    km::ErrorCode getErrorCode() const { return mError; }

    // Get upgraded blob if key was upgraded
    std::optional<std::string> getUpgradedBlob() const { return mUpgradedBlob; }

    // Call "update" repeatedly until all of the input is consumed, and
    // concatenate the output. Return true on success.
    template <class TI, class TO>
    bool updateCompletely(TI& input, TO* output) {
        if (output) output->clear();
        return updateCompletely(input.data(), input.size(), [&](const char* b, size_t n) {
            if (output) std::copy(b, b + n, std::back_inserter(*output));
        });
    }

    // Finish and write the output to this string, unless pointer is null.
    bool finish(std::string* output);

    // Move constructor
    KeymasterOperation(KeymasterOperation&& rhs) { *this = std::move(rhs); }

    // Construct an object in an error state for error returns
    KeymasterOperation()
        : mDevice{nullptr}, mOpHandle{0}, mError{km::ErrorCode::UNKNOWN_ERROR} {}

    // Move Assignment
    KeymasterOperation& operator=(KeymasterOperation&& rhs) {
        mDevice = rhs.mDevice;
        rhs.mDevice = nullptr;
        mOpHandle = rhs.mOpHandle;
        rhs.mOpHandle = 0;
        mError = rhs.mError;
        rhs.mError = km::ErrorCode::UNKNOWN_ERROR;
        mUpgradedBlob = std::move(rhs.mUpgradedBlob);
        rhs.mUpgradedBlob = std::nullopt;
        return *this;
    }

  private:
    KeymasterOperation(KmDevice* d, uint64_t h)
        : mDevice{d}, mOpHandle{h}, mError{km::ErrorCode::OK} {}

    KeymasterOperation(KmDevice* d, uint64_t h, const std::string& upgradedBlob)
        : mDevice{d}, mOpHandle{h}, mError{km::ErrorCode::OK},
          mUpgradedBlob{upgradedBlob} {}

    KeymasterOperation(km::ErrorCode error)
        : mDevice{nullptr}, mOpHandle{0}, mError{error} {}

    bool updateCompletely(const char* input, size_t inputLen,
                          const std::function<void(const char*, size_t)> consumer);

    KmDevice* mDevice;
    uint64_t mOpHandle;
    km::ErrorCode mError;
    std::optional<std::string> mUpgradedBlob;

    DISALLOW_COPY_AND_ASSIGN(KeymasterOperation);
    friend class Keymaster;
};

// Wrapper for Keymaster device for methods that start a KeymasterOperation or are not
// part of one. Uses raw HIDL Keymaster V4.0 interface directly.
class Keymaster {
  public:
    Keymaster();

    // false if we failed to open the keymaster device.
    explicit operator bool() { return mDevice.get() != nullptr; }

    // Generate a key using keymaster from the given params.
    // Uses keymint AuthorizationSet for TWRP compatibility
    bool generateKey(const km::AuthorizationSet& inParams, std::string* key);

    // Exports a keymaster key with STORAGE_KEY tag wrapped with a per-boot ephemeral key
    // Note: This may not be supported on all devices
    bool exportKey(const KeyBuffer& kmKey, std::string* key);

    // If the keymaster supports it, permanently delete a key.
    bool deleteKey(const std::string& key);

    // Replace stored key blob in response to KM_ERROR_KEY_REQUIRES_UPGRADE.
    bool upgradeKey(const std::string& oldKey, const km::AuthorizationSet& inParams,
                    std::string* newKey);

    // Get key characteristics to determine key type and parameters
    bool getKeyCharacteristics(const std::string& key, km::AuthorizationSet* hwEnforced,
                               km::AuthorizationSet* swEnforced);

    // Begin a new cryptographic operation, collecting output parameters if pointer is non-null
    // Uses keymint AuthorizationSet for TWRP compatibility
    // KeyPurpose is extracted from inParams TAG_PURPOSE
    KeymasterOperation begin(const std::string& key, const km::AuthorizationSet& inParams,
                             km::AuthorizationSet* outParams);

    // Begin with HardwareAuthToken for user-authenticated keys
    KeymasterOperation begin(const std::string& key, const km::AuthorizationSet& inParams,
                             km::AuthorizationSet* outParams,
                             const km_hidl::HardwareAuthToken& authToken);

    // Check if device is secure (TEE backed)
    bool isSecure();

    // Tell all Keymint devices that early boot has ended and early boot-only keys can no longer
    // be created or used. For HIDL V4.0, this is a no-op.
    static void earlyBootEnded();

    // Tell all Keymint devices to delete all rollback-protected keys.
    // For HIDL V4.0, this attempts to delete all keys.
    static void deleteAllKeys();

  public:
    // Error conversion (public for KeymasterOperation access)
    static km::ErrorCode convertErrorFromHidl(km_hidl::ErrorCode error);

  private:
    android::sp<KmDevice> mDevice;
    km_hidl::SecurityLevel mSecurityLevel = km_hidl::SecurityLevel::SOFTWARE;
    static bool hmacKeyGenerated;

    // Safe HMAC key agreement (won't crash on failure)
    void safePerformHmacKeyAgreement();

    // Convert keymint AuthorizationSet to HIDL AuthorizationSet
    static km_hidl::AuthorizationSet convertToHidl(const km::AuthorizationSet& keymintParams);

    // Convert HIDL AuthorizationSet to keymint AuthorizationSet
    static km::AuthorizationSet convertFromHidl(const km_hidl::AuthorizationSet& hidlParams);

    // Convert keymint ErrorCode to HIDL ErrorCode
    static km_hidl::ErrorCode convertErrorToHidl(km::ErrorCode error);

    // Extract KeyPurpose from AuthorizationSet
    static std::optional<km_hidl::KeyPurpose> extractPurpose(const km::AuthorizationSet& params);

    DISALLOW_COPY_AND_ASSIGN(Keymaster);
};

}  // namespace vold
}  // namespace android

#endif
