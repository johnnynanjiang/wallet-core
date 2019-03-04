#include <gtest/gtest.h>

#include "../../src/HDWallet.h"
#include "../../src/HexCoding.h"
#include "../../src/Checksum.h"
#include "../TWTestUtilities.h"
#include <TrezorCrypto/bip32.h>
#include <TrezorCrypto/base32.h>
#include <TrezorCrypto/curves.h>

using namespace TW;

const char* bip39Seed = "7ae6f661157bda6492f6162701e570097fc726b6235011ea5ad09bf04986731ed4d92bc43cbdee047b60ea0dd1b1fa4274377c9bf5bd14ab1982c272d8076f29";;
std::shared_ptr<TWHDWallet> wallet;

TEST(Stellar, SeedFromMnemonic) {
    wallet = WRAP(TWHDWallet, TWHDWalletCreateWithMnemonic(MNEMONIC.get(), PASSPHRASE.get()));

    assertSeedEq(wallet, bip39Seed);
}

TEST(Stellar, MasterKey) {
    auto masterPrivateKey = WRAP(TWPrivateKey, TWHDWalletGetMasterKey(wallet.get(), TWCoinTypeStellar));

    EXPECT_EQ(hex(masterPrivateKey.get()->impl.bytes), "2d4f374ece128e412067b4df6709257a249a7750fc8124262cf8b08a97f24fad");
}

TEST(Stellar, Path_M_44_148_PrivateKey) {
    auto privateKey_m_44_148 = WRAP(TWPrivateKey, TWHDWalletGetKeyToCoinLevel(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar));

    EXPECT_EQ(hex(privateKey_m_44_148.get()->impl.bytes), "1cf9c883a02479083712dcc6ed7e70657a3cfc156ae3082de96f3f5fc09bd6c4");
}

TEST(Stellar, Path_M_44_148_X_PrivateKey) {
    auto privateKey_m_44_148_0 = WRAP(TWPrivateKey, TWHDWalletGetKeyToAccountLevel(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0));
    auto privateKey_m_44_148_1 = WRAP(TWPrivateKey, TWHDWalletGetKeyToAccountLevel(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 1));

    EXPECT_EQ(hex(privateKey_m_44_148_0.get()->impl.bytes), "4fd1cb3c9c15c171b7b90dc3fefc7b2fc54de09b869cc9d6708d26b114e8d9a5");
    EXPECT_EQ(hex(privateKey_m_44_148_1.get()->impl.bytes), "afcb27720af99a95b6cb3fd660c9a834ef08d1f4654a8584b4d70734af734e7f");
}

TEST(Stellar, Path_M_44_148_X_PublicKey) {
    auto privateKey_m_44_148_0 = WRAP(TWPrivateKey, TWHDWalletGetKeyToAccountLevel(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar, 0));
    ed25519_public_key publicKey;

    ed25519_publickey(privateKey_m_44_148_0.get()->impl.bytes.data(), publicKey);

    EXPECT_EQ(hex(publicKey), "a362c6b07f6f2fa3922897bff2aaaf9c74ed7b3ee43a98ff2dbfb6fd726e1377");
}

TEST(Stellar, PublicKeyToAccountId) {
    uint8_t ACCOUNT_ID_VERSION_CODE = 6 << 3;
    uint8_t accountId[35] = {0};
    const char *publicKey = "a362c6b07f6f2fa3922897bff2aaaf9c74ed7b3ee43a98ff2dbfb6fd726e1377";

    accountId[0] = ACCOUNT_ID_VERSION_CODE;

    EXPECT_EQ(hex(accountId), "3000000000000000000000000000000000000000000000000000000000000000000000");

    auto publicKeyData = parse_hex(publicKey);
    std::copy(publicKeyData.begin(), publicKeyData.end(), accountId + 1);

    EXPECT_EQ(hex(accountId), "30a362c6b07f6f2fa3922897bff2aaaf9c74ed7b3ee43a98ff2dbfb6fd726e13770000");

    uint16_t checksum = Checksum::crc16(accountId, 1 + 32 + 2);
    std::string checksumHex = hex(checksum);
    EXPECT_EQ(checksumHex, "010f");

    accountId[1 + 32] = checksum >> 8;
    accountId[1 + 32 + 1] = (uint8_t)checksum;

    EXPECT_EQ(hex(accountId), "30a362c6b07f6f2fa3922897bff2aaaf9c74ed7b3ee43a98ff2dbfb6fd726e1377010f");

    char accountIdBase32[64] = {0};
    base32_encode(accountId, 35, accountIdBase32, 64, BASE32_ALPHABET_RFC4648);

    EXPECT_EQ(std::string(accountIdBase32), "GCRWFRVQP5XS7I4SFCL374VKV6OHJ3L3H3SDVGH7FW73N7LSNYJXOAIP");
}

/*
    Test cases @ Stellar
    https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0005.md#key-derivation-for-ed25519
*/
TEST(Stellar, ReferenceTests) {
    auto wallet = WRAP(TWHDWallet, TWHDWalletCreateWithMnemonic(STRING("illness spike retreat truth genius clock brain pass fit cave bargain toe").get(), STRING("").get()));
    const char* bip39Seed = "e4a5a632e70943ae7f07659df1332160937fad82587216a4c64315a0fb39497ee4a01f76ddab4cba68147977f3a147b6ad584c41808e8238a07f6cc4b582f186";

    assertSeedEq(wallet, bip39Seed);

    auto privateKey_m_44_148 = WRAP(TWPrivateKey, TWHDWalletGetKeyToCoinLevel(wallet.get(), TWPurposeBIP44, TWCoinTypeStellar));

    EXPECT_EQ(hex(privateKey_m_44_148.get()->impl.bytes), "e0eec84fe165cd427cb7bc9b6cfdef0555aa1cb6f9043ff1fe986c3c8ddd22e3");
}