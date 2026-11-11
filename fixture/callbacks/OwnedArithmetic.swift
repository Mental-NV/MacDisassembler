@inline(never) public func ownedAdd(_ a: UInt, _ b: UInt) -> UInt { a &+ b }
@inline(never) public func ownedScaledAdd(_ a: UInt, _ b: UInt) -> UInt { a &+ (b << 3) }
@inline(never) public func ownedLogicalRightAdd(_ a: UInt, _ b: UInt) -> UInt { a &+ (b >> 3) }
@inline(never) public func ownedArithmeticRightAdd(_ a: Int, _ b: Int) -> Int { a &+ (b >> 3) }
@inline(never) public func ownedAdd32(_ a: UInt32, _ b: UInt32) -> UInt32 { a &+ b }
@inline(never) public func ownedScaledAdd32(_ a: UInt32, _ b: UInt32) -> UInt32 { a &+ (b << 3) }
@inline(never) public func ownedPointerOffset(_ p: UnsafePointer<UInt64>, _ n: Int) -> UnsafePointer<UInt64> { p.advanced(by: n) }
@inline(never) public func ownedExtendedAdd(_ a: UInt, _ b: UInt32) -> UInt { a &+ UInt(b) }
@inline(never) public func ownedCheckedAdd(_ a: UInt, _ b: UInt) -> UInt { a + b }
