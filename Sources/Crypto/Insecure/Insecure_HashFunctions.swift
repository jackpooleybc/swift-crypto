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

extension Insecure {
    /// The SHA-1 Hash Function.
    /// ⚠️ Security Recommendation: The SHA-1 hash function is no longer considered secure. We strongly recommend using the SHA-256 hash function instead.
    public struct SHA1: HashFunctionImplementationDetails {
        public static var blockByteCount: Int = 64
        public typealias Digest = Insecure.SHA1Digest
        public static var byteCount = 20
        var impl: DigestImpl<SHA1>

        /// Initializes the hash function instance.
        public init() {
            impl = DigestImpl()
        }

        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            impl.update(data: bufferPointer)
        }

        /// Returns the digest from the data input in the hash function instance.
        ///
        /// - Returns: The digest of the inputted data
        public func finalize() -> Self.Digest {
            return impl.finalize()
        }
    }

    /// The MD5 Hash Function.
    /// ⚠️ Security Recommendation: The MD5 hash function is no longer considered secure. We strongly recommend using the SHA-256 hash function instead.
    public struct MD5: HashFunctionImplementationDetails {
        public static var blockByteCount: Int = 64
        public typealias Digest = Insecure.MD5Digest
        public static var byteCount = 16
        var impl: DigestImpl<MD5>

        /// Initializes the hash function instance.
        public init() {
            impl = DigestImpl()
        }

        public mutating func update(bufferPointer: UnsafeRawBufferPointer) {
            impl.update(data: bufferPointer)
        }

        /// Returns the digest from the data input in the hash function instance.
        ///
        /// - Returns: The digest of the inputted data
        public func finalize() -> Self.Digest {
            return impl.finalize()
        }
    }
}
