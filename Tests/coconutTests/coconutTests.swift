import XCTest
@testable import coconut

class coconutTests: XCTestCase {
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        XCTAssertEqual(coconut().text, "Hello, World!")
    }


    static var allTests : [(String, (coconutTests) -> () throws -> Void)] {
        return [
            ("testExample", testExample),
        ]
    }
}
