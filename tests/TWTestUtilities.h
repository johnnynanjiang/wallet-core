// Copyright © 2017-2019 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.
#pragma once

#include <TrustWalletCore/TWData.h>
#include <TrustWalletCore/TWString.h>
#include <TrustWalletCore/TWHDWallet.h>
#include <gtest/gtest.h>

#include "../src/HDWallet.h"

#define WRAP(type, x) std::shared_ptr<type>(x, type##Delete)
#define WRAPD(x) std::shared_ptr<TWData>(x, TWDataDelete)
#define WRAPS(x) std::shared_ptr<TWString>(x, TWStringDelete)
#define STRING(x) std::shared_ptr<TWString>(TWStringCreateWithUTF8Bytes(x), TWStringDelete)
#define DATA(x) std::shared_ptr<TWData>(TWDataCreateWithHexString(STRING(x).get()), TWDataDelete)

inline void assertStringsEqual(std::shared_ptr<TWString>& string, const char* expected) {
    ASSERT_STREQ(TWStringUTF8Bytes(string.get()), expected);
}

inline void assertHexEqual(std::shared_ptr<TWData>& data, const char* expected) {
    auto hex = WRAPS(TWStringCreateWithHexData(data.get()));
    assertStringsEqual(hex, expected);
}

inline void assertSeedEq(std::shared_ptr<TWHDWallet>& wallet, const char* expected) {
    auto seed = WRAPD(TWHDWalletSeed(wallet.get()));
    assertHexEqual(seed, expected);
}

const auto fixture_mnemonic = STRING("ripple scissors kick mammal hire column oak again sun offer wealth tomorrow wagon turn fatal");
const auto fixture_passphrase = STRING("TREZOR");