import PackageDescription

let package = Package(
    name: "coconut",
    dependencies: [
        .Package(url: "https://github.com/leaves615/SwiftSockets", majorVersion: 0, minor: 3)
    ]
)
