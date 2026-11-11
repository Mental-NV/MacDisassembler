// Owned no-call writer contrast. Compile for static inspection; do not execute.
@inline(never) public func ownedPointerWriter(_ destination: UnsafeMutablePointer<Int>, _ value: Int) {
    destination.pointee = value
}
@inline(never) public func makeOwnedPointerCallback(_ destination: UnsafeMutablePointer<Int>) -> (Int) -> Void {
    return { value in ownedPointerWriter(destination, value) }
}
