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

import Foundation

protocol DigestValidator {
    associatedtype Signature
    func isValidSignature<D: Digest>(_ signature: Signature, for digest: D) -> Bool
}

protocol DataValidator {
    associatedtype Signature
    func isValidSignature<D: DataProtocol>(_ signature: Signature, for signedData: D) -> Bool
}

extension Curve25519.Signing {
    static var signatureLength: Int {
        return 64
    }
}

extension Curve25519.Signing.PublicKey: DataValidator {
    typealias Signature = Data
    
    /// Verifies an EdDSA signature over Curve25519.
    ///
    /// - Parameters:
    ///   - signature: The 64-bytes signature to verify.
    ///   - data: The digest that was signed.
    /// - Returns: True if the signature is valid. False otherwise.
    public func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool {
        return self.openSSLIsValidSignature(signature, for: data)
    }
}

extension Curve25519.Signing.PrivateKey: Signer {
    /// Generates an EdDSA signature over Curve25519.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The 64-bytes signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> Data {
        return try self.openSSLSignature(for: data)
    }
}
