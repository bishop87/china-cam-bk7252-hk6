"""Execute the vendor pixel setup offline; no UART, network or flash writes."""
import hashlib
import json
import struct

from build_stock_patch import ROOT
from verify_stock_patch import machine, call


def main():
    sources = [
        ("stock", "analysis/original/app-payload.bin",
         "831dc94bb967f84811c4ad8b8e7211f2b4ed364dc235a7f4e2dbfd44acba831c"),
        ("EXP2D", "dist/hk6-stock-lan-exp2d/hk6-stock-lan-exp2d.bin",
         "7e6e71eeb8463159d8638b25d6f18ef9f4beb290d657dbefe91b08a3ff0161c4"),
    ]
    results = []
    routines = []
    for name, path, expected_sha in sources:
        data = (ROOT / path).read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        assert digest == expected_sha
        routines.append(data[0x41730:0x41760])
        cfg = struct.unpack_from("<I", data, 0x41758)[0]
        cases = []
        for mode, expected in ((0, (40, 22)), (1, (80, 44))):
            uc = machine(data, 0x10000)
            call(uc, 0x51731, [mode], count=100)
            units = struct.unpack("<HH", bytes(uc.mem_read(cfg + 0x18, 4)))
            assert units == expected
            cases.append(dict(mode=mode, encoder_units=list(units),
                              dimensions=[v * 8 for v in units]))
        results.append(dict(source=name, sha256=digest, cases=cases))
    assert routines[0] == routines[1]
    report = dict(
        routine="0x51730", config="0x40d2c8",
        unchanged_from_stock=True, results=results,
        scope="Actual Thumb pixel-setup routine executed in Unicorn. "
              "No hardware emulation or live profile changes. "
              "Units of 8 pixels established by SDK encoder definitions.")
    out = ROOT / "analysis/original/reverse/encoder-dimensions.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    print(out)


if __name__ == "__main__":
    main()
