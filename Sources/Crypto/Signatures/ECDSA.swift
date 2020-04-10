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
// MARK: - Generated file, do NOT edit
// any edits of this file WILL be overwritten and thus discarded
// see section `gyb` in `README` for details.

protocol NISTECDSASignature {
    init<D: DataProtocol>(rawRepresentation: D) throws
    init<D: DataProtocol>(derRepresentation: D) throws
    var derRepresentation: Data { get }
    var rawRepresentation: Data { get }
}

protocol NISTSigning {
    associatedtype PublicKey: NISTECPublicKey & DataValidator & DigestValidator
    associatedtype PrivateKey: NISTECPrivateKey & Signer
    associatedtype ECDSASignature: NISTECDSASignature
}

// MARK: - P256 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension P256.Signing {
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P256.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P256.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            try self.init(openSSLDERSignature: derRepresentation)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            return self.openSSLDERRepresentation
        }
    }
}

extension P256.Signing: NISTSigning {}

// MARK: - P256 + PrivateKey
extension P256.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the P256 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> P256.Signing.ECDSASignature {
        return try self.openSSLSignature(for: digest)
    }
 }

 extension P256.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the P256 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> P256.Signing.ECDSASignature {
        return try self.signature(for: SHA256.hash(data: data))
    }
 }

extension P256.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the P256 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: P256.Signing.ECDSASignature, for digest: D) -> Bool {
        return self.openSSLIsValidSignature(signature, for: digest)
    }
 }

 extension P256.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the P256 elliptic curve.
    /// SHA256 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: P256.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA256.hash(data: data))
    }
 }

// MARK: - P384 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension P384.Signing {
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P384.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P384.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            try self.init(openSSLDERSignature: derRepresentation)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            return self.openSSLDERRepresentation
        }
    }
}

extension P384.Signing: NISTSigning {}

// MARK: - P384 + PrivateKey
extension P384.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the P384 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> P384.Signing.ECDSASignature {
        return try self.openSSLSignature(for: digest)
    }
 }

 extension P384.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the P384 elliptic curve.
    /// SHA384 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> P384.Signing.ECDSASignature {
        return try self.signature(for: SHA384.hash(data: data))
    }
 }

extension P384.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the P384 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: P384.Signing.ECDSASignature, for digest: D) -> Bool {
        return self.openSSLIsValidSignature(signature, for: digest)
    }
 }

 extension P384.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the P384 elliptic curve.
    /// SHA384 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: P384.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA384.hash(data: data))
    }
 }

// MARK: - P521 + Signing
/// An ECDSA (Elliptic Curve Digital Signature Algorithm) Signature
extension P521.Signing {
    public struct ECDSASignature: ContiguousBytes, NISTECDSASignature {
        /// Returns the raw signature.
        /// The raw signature format for ECDSA is r || s
        public var rawRepresentation: Data

        /// Initializes ECDSASignature from the raw representation.
        /// The raw signature format for ECDSA is r || s
        /// As defined in https://tools.ietf.org/html/rfc4754
        public init<D: DataProtocol>(rawRepresentation: D) throws {
            guard rawRepresentation.count == 2 * P521.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = Data(rawRepresentation)
        }
        
        internal init(_ dataRepresentation: Data) throws {
            guard dataRepresentation.count == 2 * P521.CurveDetails.coordinateByteCount else {
                throw CryptoKitError.incorrectParameterSize
            }

            self.rawRepresentation = dataRepresentation
        }

        var composite: (r: Data, s: Data) {
            let combined = rawRepresentation
            assert(combined.count % 2 == 0)
            let half = combined.count / 2
            return (combined.prefix(upTo: half), combined.suffix(from: half))
        }

        /// Initializes ECDSASignature from the DER representation.
        public init<D: DataProtocol>(derRepresentation: D) throws {
            try self.init(openSSLDERSignature: derRepresentation)
        }

        public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.rawRepresentation.withUnsafeBytes(body)
        }

        /// A DER-encoded representation of the signature
        public var derRepresentation: Data {
            return self.openSSLDERRepresentation
        }
    }
}

extension P521.Signing: NISTSigning {}

// MARK: - P521 + PrivateKey
extension P521.Signing.PrivateKey: DigestSigner {
    ///  Generates an ECDSA signature over the P521 elliptic curve.
    ///
    /// - Parameter digest: The digest to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature
    public func signature<D: Digest>(for digest: D) throws -> P521.Signing.ECDSASignature {
        return try self.openSSLSignature(for: digest)
    }
 }

 extension P521.Signing.PrivateKey: Signer {
    /// Generates an ECDSA signature over the P521 elliptic curve.
    /// SHA512 is used as the hash function.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The ECDSA Signature.
    /// - Throws: If there is a failure producing the signature.
    public func signature<D: DataProtocol>(for data: D) throws -> P521.Signing.ECDSASignature {
        return try self.signature(for: SHA512.hash(data: data))
    }
 }

extension P521.Signing.PublicKey: DigestValidator {
    /// Verifies an ECDSA signature over the P521 elliptic curve.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - digest: The digest that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: Digest>(_ signature: P521.Signing.ECDSASignature, for digest: D) -> Bool {
        return self.openSSLIsValidSignature(signature, for: digest)
    }
 }

 extension P521.Signing.PublicKey: DataValidator {
    /// Verifies an ECDSA signature over the P521 elliptic curve.
    /// SHA512 is used as the hash function.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify
    ///   - data: The data that was signed.
    /// - Returns: True if the signature is valid, false otherwise.
    public func isValidSignature<D: DataProtocol>(_ signature: P521.Signing.ECDSASignature, for data: D) -> Bool {
        return self.isValidSignature(signature, for: SHA512.hash(data: data))
    }
 }
