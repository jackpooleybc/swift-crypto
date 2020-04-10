//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// Errors thrown in CryptoKit
/// - incorrectKeySize: A key is being deserialized with an incorrect key size.
/// - incorrectParameterSize: The number of bytes passed for a given argument is incorrect.
/// - authenticationFailure: The authentication tag or signature is incorrect.
/// - underlyingCoreCryptoError: An unexpected error at a lower-level occured.
public enum CryptoKitError: Error {
    case incorrectKeySize
    case incorrectParameterSize
    case authenticationFailure
    case underlyingCoreCryptoError(error: Int32)
}
