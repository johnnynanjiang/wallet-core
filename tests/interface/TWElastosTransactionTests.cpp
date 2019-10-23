
// Copyright © 2017-2019 Trust Wallet.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#include "TWTestUtilities.h"

#include "Bitcoin/OutPoint.h"
#include "Bitcoin/TransactionBuilder.h"
#include "Bitcoin/TransactionSigner.h"
#include "HexCoding.h"
#include "PublicKey.h"

#include <TrustWalletCore/TWBitcoinScript.h>
#include <TrustWalletCore/TWHDWallet.h>

#include <gtest/gtest.h>

using namespace TW;
using namespace Bitcoin;

TEST(ElastosTransaction, SignTransaction) {
    /*
        https://zuohuahua.github.io/Elastos.Tools.Creator.Capsule/
        Mnemonic - shoot island position soft burden budget tooth cruel issue economy destroy above
        m/44'/0'/0'/0/0 Address - EMhz3DQtQBYaQPzAps6MziyQZqhE8MjeTR
        m/44'/0'/0'/0/0 Private key in bytes - 1daf5ce87ed1114ed9f6e3417b4c3031ce048ece44c286d3c646a2ecee9c40a4
        m/44'/0'/0'/0/0 Public key in bytes - 024bd8342acbfac4582705e93b573f5c01de16425b7f42f3d9f8892cefe32fa7af
        utxo - https://blockchain.elastos.org/tx/20b9ecfcd30b1a8ef51f8f5f4aaf86431eb76b2295197fd76ead2d4712e05aa6
        tx - https://blockchain.elastos.org/tx/24f20e41b5bc5b7572eff6c260a62e6f605fd7f0ad0da34b8555081922c9d8ac
    */

    const int64_t utxo_amount = 99950280;
    const int64_t amount = 600000;
    const int64_t fee = 486;
    std::cout << "1" << std::endl;
    auto input = Bitcoin::Proto::SigningInput();
    input.set_hash_type(TWBitcoinSigHashTypeAll);
    input.set_amount(amount);
    input.set_byte_fee(1);
    input.set_to_address("EMhz3DQtQBYaQPzAps6MziyQZqhE8MjeTR");
    input.set_change_address("EXMcNCnHJiMB2i6eFxiokL5VskFbyxBxbT");
    input.set_coin_type(TWCoinTypeElastos);
    std::cout << "2" << std::endl;
    auto hash0 = DATA("a65ae012472dad6ed77f1995226bb71e4386af4a5f8f1ff58e1a0bd3fcecb920");
    auto utxo0 = input.add_utxo();
    utxo0->mutable_out_point()->set_hash(TWDataBytes(hash0.get()), TWDataSize(hash0.get()));
    utxo0->mutable_out_point()->set_index(0);
    utxo0->mutable_out_point()->set_sequence(UINT32_MAX);
    utxo0->set_amount(utxo_amount);
    auto script0 = parse_hex("76a9145d6e33f3a108bbcc586cbbe90994d5baf5a9cce488ac");
    utxo0->set_script(script0.data(), script0.size());
    std::cout << "3" << std::endl;
    auto utxoKey0 = DATA("1daf5ce87ed1114ed9f6e3417b4c3031ce048ece44c286d3c646a2ecee9c40a4");
    input.add_private_key(TWDataBytes(utxoKey0.get()), TWDataSize(utxoKey0.get()));
    std::cout << "4" << std::endl;
    auto plan = Bitcoin::TransactionBuilder::plan(input);
    plan.amount = amount;
    plan.fee = fee;
    plan.change = utxo_amount - amount - fee;
    std::cout << "5" << std::endl;
    // Sign
    auto signer = TW::Bitcoin::TransactionSigner<TW::Bitcoin::Transaction>(std::move(input), plan);
    std::cout << "5.1" << std::endl;
    auto result = signer.sign();
    std::cout << "5.2" << std::endl;
    auto signedTx = result.payload();
    std::cout << "6" << std::endl;
    ASSERT_TRUE(result);
    ASSERT_EQ(fee, signer.plan.fee);
    std::cout << "7" << std::endl;
    Data serialized;
    signedTx.encode(false, serialized);
    ASSERT_EQ(
        hex(serialized),
        "0200018114747970653a746578742c6d73673a54657374303101d60d0979cb3b2616cc69c18afa5a779ebd3750201a47c0e891ad71643ffb6ea100000000000002b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a31027000000000000000000002131f19bb1f1a8920377e5c4a0e0a360023e207545b037db964a231458d2d6ffd5ea18944c4f90e63d547c5d3b9874df66a4ead0a3f4a6f5050000000000000000219bc87495b56f88cae064ab1fd0494f77840b789500000000014140bde99380a719ef8b7eaf6d8876c63db5ca346f797d8da5c0ebc03ccb6e468b0bc5b506537786988658fc3bd42272aa38669b2c612238a7aa88319fbbf6c6071923210298b58ed858c563fb98d3a8f95414a6390deb0da2475bc200cfb0c639525a06d7ac"
    ); 
}

TEST(ElastosTransaction, LockScripts) {
    // P2PKH    
    // https://blockchain.elastos.org/tx/24f20e41b5bc5b7572eff6c260a62e6f605fd7f0ad0da34b8555081922c9d8ac
    
    auto script = WRAP(TWBitcoinScript, TWBitcoinScriptBuildForAddress(STRING("EMhz3DQtQBYaQPzAps6MziyQZqhE8MjeTR").get(), TWCoinTypeElastos));
    auto scriptData = WRAPD(TWBitcoinScriptData(script.get()));
    assertHexEqual(scriptData, "76a9149451f4546e09fc2e49ef9b5303924712ec2b038e88ac");
}
