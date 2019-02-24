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

    auto key0 = WRAP(TWPrivateKey, TWHDWalletGetKey(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 0));
    auto key1 = WRAP(TWPrivateKey, TWHDWalletGetKey(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 1));

    auto publicKey0 = TWPrivateKeyGetPublicKey(key0.get(), true);
    auto publicKey0Data = WRAPD(TWPublicKeyData(publicKey0));

    auto publicKey1 = TWPrivateKeyGetPublicKey(key1.get(), true);
    auto publicKey1Data = WRAPD(TWPublicKeyData(publicKey1));

    // TODO by JNJ: to fix the assertions by implementing Stellar address derivation
    /*
    assertHexEqual(publicKey0Data, "a362c6b07f6f2fa3922897bff2aaaf9c74ed7b3ee43a98ff2dbfb6fd726e1377");
    assertHexEqual(publicKey1Data, "b10ec09cfc909287f09fbabd93862e17dd0697c5b897f8117af27e9004c2cae0");
    */
}