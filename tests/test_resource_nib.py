import hashlib
import plistlib
import struct
from unittest.mock import patch

from macscope import cli, engine, resource_nib
from test_core import TemporaryCase


def fixture(connector="NSNibControlConnector", destination=4):
    destination_field = ("NSDestination", 9, None) if destination is None else ("NSDestination", 10, destination)
    nodes = [
        ("NSObject", [("IB.objectdata", 10, 1)]),
        ("NSIBObjectData", [("NSConnections", 10, 2)]),
        ("NSArray", [("UINibEncoderEmptyKey", 10, 3)]),
        (connector, [("NSSource", 10, 5), destination_field, ("NSLabel", 10, 8)]),
        ("NSCustomObject", [("NSClassName", 10, 9)]),
        ("NSButton", [("NSCell", 10, 6)]),
        ("NSButtonCell", [("NSContents", 10, 7)]),
        ("NSString", [("NS.bytes", 8, b"Week")]),
        ("NSString", [("NS.bytes", 8, b"calendarDayDuration:")]),
        ("NSString", [("NS.bytes", 8, b"OwnedCalendarController")]),
    ]
    classes = list(dict.fromkeys(name for name, _ in nodes))
    keys = list(dict.fromkeys(key for _, fields in nodes for key, _, _ in fields))
    objects, values, count = bytearray(), bytearray(), 0
    for name, fields in nodes:
        objects.extend(number(classes.index(name), count, len(fields)))
        count += len(fields)
        for key, tag, value in fields:
            values.extend(number(keys.index(key)) + bytes([tag]))
            if tag == 10:
                values.extend(struct.pack("<I", value))
            elif tag == 8:
                values.extend(number(len(value)) + value)
    names = b"".join(number(len(key)) + key.encode() for key in keys)
    class_names = b"".join(number(len(name) + 1, 0) + name.encode() + b"\0" for name in classes)
    header = struct.pack("<10I", 1, 10, len(nodes), 50, len(keys), 50 + len(objects),
                         count, 50 + len(objects) + len(names), len(classes),
                         50 + len(objects) + len(names) + len(values))
    return b"NIBArchive" + header + objects + names + values + class_names


def number(*items):
    return bytes(value | 0x80 for value in items)


class ResourceNibTests(TemporaryCase):
    def test_nib_cli_pages_exact_declarations_and_does_not_start_an_engine(self):
        app = self.root / "Calendar.app"
        contents = app / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        (contents / "MacOS" / "Calendar").write_bytes(b"owned fixture")
        (contents / "Info.plist").write_bytes(plistlib.dumps({"CFBundleExecutable": "Calendar"}))
        resource = contents / "Calendar.nib"
        raw = fixture()
        resource.write_bytes(raw)
        words = ["resources", "nib", str(app), "--file", "Contents/Calendar.nib"]

        def run(*extra):
            return cli.execute(cli.parser().parse_args([*words, *extra]))

        with patch.object(engine, "dependencies", side_effect=AssertionError("nib query started the engine")):
            first = run("--limit", "1")
            self.assertEqual(first["data"]["sha256"], hashlib.sha256(raw).hexdigest())
            action, = first["data"]["records"]
            self.assertEqual((action["kind"], action["label"]), ("action", "calendarDayDuration:"))
            self.assertEqual(action["source"]["archive_class"], "NSButton")
            self.assertEqual(action["destination"]["declared_class"], "OwnedCalendarController")
            cursor = first["coverage"]["next_cursor"]
            label, = run("--cursor", cursor)["data"]["records"]
            self.assertEqual((label["kind"], label["label"]), ("button_label", "Week"))
            self.assertEqual(label["control"], action["source"])
            self.error("stale_cursor", run, "--kind", "labels", "--cursor", cursor)
            self.error("output_input_conflict", run, "--output", str(resource), "--force")
            resource.write_bytes(fixture("NSNibBindingConnector"))
            self.error("stale_cursor", run, "--cursor", cursor)
            partial = run()
            self.assertEqual(partial["status"], "partial")
            self.assertIsNone(partial["coverage"]["known_total"])
            self.assertEqual(partial["data"]["records"][0]["reason"], "nib_connection_class_unsupported")
            self.assertEqual(partial["data"]["records"][1], label)

    def test_archive_offsets_value_kinds_and_references_are_bounded(self):
        raw = fixture()
        older = raw[:14] + struct.pack("<I", 9) + raw[18:]
        self.assertEqual(resource_nib.parse(older)[0], resource_nib.parse(raw)[0])
        self.error("resource_nib_format", resource_nib.parse, b"bplist00")
        for broken in (raw[:49], raw[:-1], raw + b"\0", fixture(destination=99),
                       raw[:22] + struct.pack("<I", 49) + raw[26:]):
            self.error("resource_nib_invalid", resource_nib.parse, broken)
        start_values, = struct.unpack_from("<I", raw, 38)
        unknown = raw[:start_values + 1] + b"\xff" + raw[start_values + 2:]
        self.error("resource_nib_value_type", resource_nib.parse, unknown)
        with patch.object(resource_nib, "MAX_OBJECTS", 4):
            self.error("resource_nib_limit", resource_nib.parse, raw)

    def test_missing_endpoint_keeps_the_declaration_partial(self):
        nodes, _ = resource_nib.parse(fixture(destination=None))
        rows, gaps = resource_nib.connections(nodes)
        row, = rows
        self.assertEqual(gaps, {"nib_connection_fields_unavailable"})
        self.assertEqual(row["label"], "calendarDayDuration:")
        self.assertIsNone(row["destination"])
        self.assertEqual(row["status"], "partial")
