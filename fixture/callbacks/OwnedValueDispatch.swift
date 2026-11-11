// Owned static source oracle. Compile for analysis; do not execute.
public struct OwnedValueRecord {
    public var value: Int64
    public var revision: UInt64
    public init(value: Int64, revision: UInt64) {
        self.value = value
        self.revision = revision
    }
}
public protocol OwnedValueSink {
    func save(_ record: OwnedValueRecord)
}
public final class OwnedCountingSink: OwnedValueSink {
    public var last: Int64 = 0
    public var saves: UInt64 = 0
    public init() {}
    @inline(never) public func save(_ record: OwnedValueRecord) {
        last = record.value
        saves &+= 1
    }
}
@inline(never) public func ownedApplyValue(_ record: inout OwnedValueRecord,
                                         _ proposed: Int64?) -> Bool {
    guard let value = proposed, value >= 0, value != record.value else { return false }
    record.value = value
    record.revision &+= 1
    return true
}
@inline(never) public func ownedUpdateAndSave(_ record: inout OwnedValueRecord,
                                            _ proposed: Int64?,
                                            _ sink: any OwnedValueSink) -> Bool {
    let changed = ownedApplyValue(&record, proposed)
    if changed { sink.save(record) }
    return changed
}
