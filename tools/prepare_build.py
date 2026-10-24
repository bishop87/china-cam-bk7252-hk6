"""Create a disposable SDK tree at a pinned commit and apply our overlay."""
import io
import json
import secrets
import sys
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK_COMMIT = "266d54fd8965a093d345c1a1cdb6ca26da6a6488"
DEST = ROOT / "build/sdk"


def replace(path, old, new):
    text = path.read_text()
    if old not in text:
        raise RuntimeError(f"Patch context missing in {path}")
    path.write_text(text.replace(old, new))


def prepare():
    if DEST.exists():
        raise SystemExit("build/sdk already exists; preserve it or remove this generated directory before preparing again")
    DEST.mkdir(parents=True)
    archive = subprocess.check_output(["git", "-C", str(ROOT / "upstream/sdk"), "archive", SDK_COMMIT])
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(DEST, filter="data")
    # The branch ships its config but the old generator references removed files.
    p = DEST / "rt-thread/tools/building.py"
    text = p.read_text()
    start = text.index("    if sys.platform == 'win32':", text.index("    beken_target = GetOption('beken')"))
    end = text.index("\n    Env = env", start)
    p.write_text(text[:start] + "    # LocalCam: keep pinned config; package separately with Python.\n" + text[end:])
    # Compile no vendor test applications or network demo shell commands.
    (DEST / "test/SConscript").write_text("group = []\nReturn('group')\n")
    replace(DEST / "function/SConscript", "src\t= Glob('*.c')",
            "src = [f for f in Glob('*.c') if os.path.basename(str(f)) != 'vbat_detect.c']")
    (DEST / "samples/SConscript").write_text("group = SConscript('ota/port/SConscript')\nReturn('group')\n")
    p = DEST / "rt-thread/components/finsh/cmd.c"
    text = p.read_text()
    start = text.index('#include <rt_ota.h>')
    end = text.index('FINSH_FUNCTION_EXPORT(version', start)
    p.write_text(text[:start] + 'long version(void) { rt_show_version(); return 0; }\n' + text[end:])
    cfg = DEST / "rtconfig.h"
    text = cfg.read_text()
    for flag in ("PKG_USING_PAHOMQTT", "PKG_USING_WEBCLIENT", "PKG_NETUTILS_TELNET", "PKG_USING_RT_OTA"):
        text = text.replace("#define " + flag + "\n", "/* LocalCam disabled: " + flag + " */\n")
    cfg.write_text(text)
    (DEST / "beken378/old_app/app.h").write_text('#include "app_pre_start.h"\nvoid app_start(void);\n')
    (DEST / "applications/main.c").write_text('''/* LocalCam entry: no SD autorun or vendor application. */
extern void app_pre_start(void);
extern void app_start(void);
int main(void) { app_pre_start(); app_start(); return 0; }
''')
    # Bound acquisition waits if the board/sensor is unsupported.
    replace(DEST / "beken378/old_app/video_work/video_buffer.c",
            "timeout = BEKEN_WAIT_FOREVER;", "timeout = 2000; /* LocalCam: milliseconds, via rtos_get_semaphore */")
    replace(DEST / "beken378/old_app/video_work/video_buffer.c",
            "if (hdr->is_eof == 1)", "if (hdr->is_eof == 1 && g_vbuf->frame_len >= 7)")
    replace(DEST / "beken378/func/camera_intf/camera_intf.c",
            'sensor->i2c_bus == (char*) &I2C2_DEV_NAME', 'strcmp(sensor->i2c_bus, I2C2_DEV_NAME) == 0')
    replace(DEST / "beken378/func/camera_intf/camera_intf.c",
            'camera_sensor_t* sensor = malloc(sizeof(camera_sensor_t));',
            'camera_sensor_t* sensor = malloc(sizeof(camera_sensor_t));\n    if (!sensor) return NULLPTR;')
    replace(DEST / "beken378/func/video_transfer/video_transfer.c",
            'camera_sensor = fake_sensor();\n                camera_intfer_init(&tvideo_st, camera_sensor);',
            'os_printf("LocalCam: no supported sensor; capture disabled.\\r\\n");')
    sync_app()
    print(DEST)


def sync_app():
    shutil.copytree(ROOT / "firmware/localcam", DEST / "localcam", dirs_exist_ok=True)
    config_path = ROOT / "firmware/local-config.json"
    if not config_path.exists():
        config_path.write_text(json.dumps(dict(mode="ap", ssid="LocalCam-HK6", password=secrets.token_urlsafe(12)), indent=2) + "\n")
        config_path.chmod(0o600)
    config = json.loads(config_path.read_text())
    if config['mode'] not in ('ap', 'station'):
        raise ValueError('mode must be ap or station')
    if not 1 <= len(config['ssid'].encode('ascii')) <= 32 or not 8 <= len(config['password'].encode('ascii')) <= 63:
        raise ValueError('Use ASCII SSID (1..32 bytes) and WPA2 password (8..63 bytes)')
    (DEST / "localcam/localcam_config.h").write_text(
        '#define LOCALCAM_MODE_AP ' + str(int(config['mode'] == 'ap')) + '\n' +
        '#define LOCALCAM_SSID ' + json.dumps(config['ssid']) + '\n' +
        '#define LOCALCAM_PASSWORD ' + json.dumps(config['password']) + '\n')


if __name__ == "__main__":
    if sys.argv[1:] == ['--sync']:
        sync_app()
    else:
        prepare()
