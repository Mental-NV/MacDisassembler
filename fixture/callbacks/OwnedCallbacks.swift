// Independently authored source oracle. Never execute an inspected fixture.
public final class OwnedCallbackBox {
    public var value: Int = 0
    public var callback: ((Int) -> Void)?
    public init() {}
    @inline(never) public func writeFirst(_ value: Int) { self.value = value }
    @inline(never) public func writeSecond(_ value: Int) { self.value = value + 1 }
    @inline(never) public func installCaptured() {
        callback = { [self] value in self.writeFirst(value) }
    }
    @inline(never) public func installAlternative(_ second: Bool) {
        if second { callback = { [self] value in self.writeSecond(value) } }
        else { callback = { [self] value in self.writeFirst(value) } }
    }
    @inline(never) public func overwrite() {
        callback = { [self] value in self.writeFirst(value) }
        callback = { [self] value in self.writeSecond(value) }
    }
    @inline(never) public func installUnknown(_ incoming: @escaping (Int) -> Void) {
        callback = incoming
    }
    @inline(never) public func invoke(_ value: Int) { callback?(value) }
}
@inline(never) public func ownedUncaptured(_ value: Int) {}
@inline(never) public func installUncaptured(_ box: OwnedCallbackBox) {
    box.callback = ownedUncaptured
}
