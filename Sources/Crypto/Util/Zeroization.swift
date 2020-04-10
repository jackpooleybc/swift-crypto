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

protocol Zeroization {
    mutating func zeroize()
}

extension UnsafeMutablePointer: Zeroization {
    /// Zeroizes the pointee
    func zeroize() {
        let size = MemoryLayout.size(ofValue: Pointee.self)
        boring_memset_s(self, size, 0, size)
    }
}

extension Array: Zeroization where Element == UInt8 {
    /// Zeroizes the array
    mutating func zeroize() {
        boring_memset_s(&self, self.count, 0, self.count)
    }
}
