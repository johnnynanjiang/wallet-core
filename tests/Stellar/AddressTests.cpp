#include <gtest/gtest.h>

#include "../../src/HDWallet.h"
#include "../../src/HexCoding.h"
#include "../TWTestUtilities.h"
#include <TrezorCrypto/bip32.h>
#include <TrezorCrypto/curves.h>

using namespace TW;

auto wallet = WRAP(TWHDWallet, TWHDWalletCreateWithMnemonic(fixture_mnemonic.get(), fixture_passphrase.get()));
const char* bip39Seed = "7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29";

TEST(Stellar, DeriveMasterKeyFromMnemonic) {
    assertSeedEq(wallet, bip39Seed);

    auto masterNode = HDNode();
    hdnode_from_seed(wallet.get()->impl.seed.data(), HDWallet::seedSize, ED25519_NAME, &masterNode);
    
    ASSERT_EQ(hex(masterNode.private_key), "2d4f374ece128e412067b4df6709257a249a7750fc8124262cf8b08a97f24fad");
}

TEST(Stellar, DeriveAddressFromSeed) {
    auto seed = STRING(bip39Seed);

    auto privateKey0 = WRAP(TWPrivateKey, TWHDWalletGetKeyEd25519(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 0));
    auto privateKey1 = WRAP(TWPrivateKey, TWHDWalletGetKeyEd25519(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 1, 0, 0));

    EXPECT_EQ(hex(privateKey0.get()->impl.bytes), "4fd1cb3c9c15c171b7b90dc3fefc7b2fc54de09b869cc9d6708d26b114e8d9a5");
    EXPECT_EQ(hex(privateKey1.get()->impl.bytes), "afcb27720af99a95b6cb3fd660c9a834ef08d1f4654a8584b4d70734af734e7f");
}