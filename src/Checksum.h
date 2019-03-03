// Copyright © 2017-2019 Trust.
//
// This file is part of Trust. The full Trust copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

#pragma once

#include <stdlib.h>

namespace TW {
namespace Checksum {

uint16_t crc16(uint8_t *bytes, uint32_t length);

}} // namespace