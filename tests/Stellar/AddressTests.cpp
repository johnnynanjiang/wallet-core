#include <gtest/gtest.h>

#include "../../src/HDWallet.h"
#include "../../src/HexCoding.h"
#include "../TWTestUtilities.h"

using namespace TW;

TEST(Stellar, DeriveAddressFromMnemonic) {
    auto wallet = WRAP(TWHDWallet, TWHDWalletCreateWithMnemonic(fixture_mnemonic.get(), fixture_passphrase.get()));

    assertSeedEq(wallet, "7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29");

    auto key0 = WRAP(TWPrivateKey, TWHDWalletGetKey(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 0));
    auto key1 = WRAP(TWPrivateKey, TWHDWalletGetKey(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0, 0, 1));

    auto publicKey0 = TWPrivateKeyGetPublicKey(key0.get(), false);
    auto publicKey0Data = WRAPD(TWPublicKeyData(publicKey0));

    auto publicKey1 = TWPrivateKeyGetPublicKey(key1.get(), false);
    auto publicKey1Data = WRAPD(TWPublicKeyData(publicKey1));

    assertHexEqual(publicKey0Data, "04629289c4d9777f051bc3fdcf01c46237390b889f2cc4ee5dd01030ef3225c03632b60a04123a71069af875bb43b9abe4b277f896f1c8faf784207e07ded890fb");
    assertHexEqual(publicKey1Data, "04c978b7bf44747ca41189a321b0c3967e1f34052c32876ed436bef421a22d339e1115e0690d27005533ff5174eb2d60a13569249f7d148b3a0bdcb514a908b68f");
}

TEST(Stellar, DeriveAddressFromSeed) {
    auto seed = STRING("7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29");
}