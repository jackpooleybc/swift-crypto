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
import XCTest
@testable import Crypto

class SharedSecretTests: XCTestCase {
    func testEqualityWithDataProtocol() throws {
        let testSecret = Array("hello, world".utf8)
        let ss = SharedSecret(ss: SecureBytes(bytes: testSecret))
        let (contiguousSecret, discontiguousSecret) = testSecret.asDataProtocols()

        XCTAssertTrue(ss == contiguousSecret)
        XCTAssertTrue(ss == discontiguousSecret)
        XCTAssertFalse(ss == DispatchData.empty)
    }
}

