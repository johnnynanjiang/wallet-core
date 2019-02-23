#include <gtest/gtest.h>

#include "../../src/HDWallet.h"
#include "../../src/HexCoding.h"
#include "../TWTestUtilities.h"

using namespace TW;

TEST(Stellar, GetSeedFromMnemonic) {
    const auto wallet = HDWallet("swift slam quote sail high remain mandate sample now stamp title among fiscal captain joy puppy ghost arrow attract ozone situate install gain mean", "");
    const auto privateKey = wallet.getKey(TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 0);
    const auto publicKeyData = privateKey.getPublicKey(true);

    EXPECT_EQ("189a8c98785ab71e8d1c9f9948b918365960fcf7f106ca03039dd2e9bef254bdb2c9ecca1aa3a7bc21ba93bf2dfc9e4bd704b536c886082dcf44caf35f24cd56", hex(wallet.seed));
    EXPECT_EQ("907662626004f22c3708148eee84770c94acdc899635cd388725930f9d7a5751", hex(privateKey.bytes));
    EXPECT_EQ("031a735c439e850ea49dec8b9c76912492d6be03553dfcddde7c046574b3b16c08", hex(publicKeyData.begin(), publicKeyData.end()));
}

TEST(Stellar, DeriveAddressFromSeed) {
    auto seed = STRING("189a8c98785ab71e8d1c9f9948b918365960fcf7f106ca03039dd2e9bef254bdb2c9ecca1aa3a7bc21ba93bf2dfc9e4bd704b536c886082dcf44caf35f24cd56");
}