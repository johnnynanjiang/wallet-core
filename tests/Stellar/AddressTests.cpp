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

    auto privateKey_m_44_148_0_0_0 = WRAP(TWPrivateKey, TWHDWalletGetKeyEd25519(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 0));
    auto privateKey_m_44_148_1_0_0 = WRAP(TWPrivateKey, TWHDWalletGetKeyEd25519(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 1, 0, 0));
    auto privateKey_m_44_148_1_0_1 = WRAP(TWPrivateKey, TWHDWalletGetKeyEd25519(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 1, 0, 1));

    EXPECT_EQ(hex(privateKey_m_44_148_0_0_0.get()->impl.bytes), "090ceb3bfc18a5994df63adb99d9e1ab4efd6e0b99f3cadc307011c88dfe3dcf");
    EXPECT_EQ(hex(privateKey_m_44_148_1_0_0.get()->impl.bytes), "bcd8e34fc099226b125b0d0efbc1bb06445bf136cdbad7b270f5cfe727bc0b47");
    EXPECT_EQ(hex(privateKey_m_44_148_1_0_1.get()->impl.bytes), "b46738be2511e5003e689ba2418cfcec6ee541b5ee74ed7476339056d819663d");
}