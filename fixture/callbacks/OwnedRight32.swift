@inline(never) public func ownedLogicalRightAdd32(_ a: UInt32, _ b: UInt32) -> UInt32 { a &+ (b >> 3) }
@inline(never) public func ownedArithmeticRightAdd32(_ a: Int32, _ b: Int32) -> Int32 { a &+ (b >> 3) }
