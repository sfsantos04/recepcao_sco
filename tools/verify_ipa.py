#!/usr/bin/env python3
"""verify_ipa.py - confere um IPA do nxnative antes de instalar.

Camadas:
  1. o zip abre e tem exatamente um Payload/<Algo>.app
  2. Info.plist dentro do .app: CFBundleIdentifier, CFBundleShortVersionString,
     CFBundleVersion, MinimumOSVersion, CFBundleSupportedPlatforms=iPhoneOS,
     CFBundleExecutable, UIFileSharingEnabled
  3. o executavel existe, modo 0755, Mach-O 64 bits thin arm64, platform=2 (iOS),
     MH_PIE ligado, minos >= 26
  4. conteudo do jogo presente: assinatura/simbolos do host (DmIOS, dmsh, nvn)
     e os recursos que fazem o app ser esse jogo, nao uma casca vazia

Uso:
  python3 verify_ipa.py Game.ipa [--expect-bundle org.nxnative.xxxx] [--min-bytes N]

Sai 0 quando todas as camadas passam, 1 com a lista do que falhou.
"""
import argparse
import hashlib
import plistlib
import struct
import sys
import zipfile

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
LC_BUILD_VERSION = 0x32
PLATFORM_IOS = 2
MH_PIE = 0x200000
MIN_IOS = 26


def fail(msgs, text):
    msgs.append(text)


def macho_info(data, msgs):
    if len(data) < 32:
        fail(msgs, "executavel curto demais para ser Mach-O (%d bytes)" % len(data))
        return None
    magic, cputype, _cpusub, _ftype, ncmds, sizeofcmds, flags, _res = struct.unpack("<8I", data[:32])
    if magic != MH_MAGIC_64:
        fail(msgs, "nao e Mach-O 64 bits little-endian (magic=0x%08X)" % magic)
        return None
    if cputype != CPU_TYPE_ARM64:
        fail(msgs, "cputype=0x%X, esperado arm64 (0x%X)" % (cputype, CPU_TYPE_ARM64))
    info = {"cputype": cputype, "flags": flags, "ncmds": ncmds, "platform": None, "minos": None}
    if not flags & MH_PIE:
        fail(msgs, "MH_PIE ausente (flags=0x%X)" % flags)

    off = 32
    end = 32 + sizeofcmds
    for _ in range(ncmds):
        if off + 8 > end or off + 8 > len(data):
            fail(msgs, "load commands truncados")
            break
        cmd, cmdsize = struct.unpack("<2I", data[off:off + 8])
        if cmdsize < 8:
            fail(msgs, "cmdsize invalido (0) em cmd 0x%X" % cmd)
            break
        if cmd == LC_BUILD_VERSION and off + 16 <= len(data):
            platform, minos, _sdk, _ntools = struct.unpack("<4I", data[off + 8:off + 24])
            info["platform"] = platform
            info["minos"] = "%d.%d" % (minos >> 16, (minos >> 8) & 0xFF)
        off += cmdsize

    if info["platform"] is None:
        fail(msgs, "sem LC_BUILD_VERSION: nao da para provar que o binario e iOS")
    elif info["platform"] != PLATFORM_IOS:
        fail(msgs, "platform=%d, esperado 2 (iOS)" % info["platform"])
    if info["minos"]:
        major = int(info["minos"].split(".")[0])
        if major < MIN_IOS:
            fail(msgs, "minos %s < %d (o host usa Metal 4)" % (info["minos"], MIN_IOS))
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ipa")
    ap.add_argument("--expect-bundle")
    ap.add_argument("--min-bytes", type=int, default=0,
                    help="tamanho minimo do executavel; abaixo disso a build e uma casca")
    a = ap.parse_args()

    msgs = []
    ok = []

    h = hashlib.sha256()
    with open(a.ipa, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    size = 0
    msgs_local = []

    try:
        z = zipfile.ZipFile(a.ipa)
    except Exception as e:  # noqa: BLE001
        print("FALHOU: nao abre como zip: %s" % e)
        return 1

    bad = z.testzip()
    if bad is not None:
        fail(msgs, "entrada corrompida no zip: %s" % bad)
    else:
        ok.append("zip integro, %d entradas" % len(z.namelist()))

    apps = sorted({n.split("/")[1] for n in z.namelist()
                   if n.startswith("Payload/") and n.count("/") >= 2 and n.split("/")[1].endswith(".app")})
    if len(apps) != 1:
        fail(msgs, "esperado 1 Payload/*.app, achei %r" % apps)
        print_report(ok, msgs)
        return 1
    app = "Payload/%s" % apps[0]
    ok.append("app unico: %s" % apps[0])

    junk = [n for n in z.namelist() if n.startswith("__MACOSX") or n.endswith(".DS_Store")]
    if junk:
        fail(msgs, "%d entradas espurias (__MACOSX/.DS_Store), ex.: %s" % (len(junk), junk[0]))

    try:
        plist = plistlib.loads(z.read(app + "/Info.plist"))
    except KeyError:
        fail(msgs, "sem %s/Info.plist" % app)
        print_report(ok, msgs)
        return 1
    except Exception as e:  # noqa: BLE001
        fail(msgs, "Info.plist ilegivel: %s" % e)
        print_report(ok, msgs)
        return 1

    bundle = plist.get("CFBundleIdentifier", "")
    ok.append("bundle id: %s" % bundle)
    ok.append("versao: %s (%s)" % (plist.get("CFBundleShortVersionString"), plist.get("CFBundleVersion")))
    ok.append("MinimumOSVersion: %s" % plist.get("MinimumOSVersion"))
    if a.expect_bundle and bundle != a.expect_bundle:
        fail(msgs, "bundle id %s != esperado %s" % (bundle, a.expect_bundle))
    if not plist.get("CFBundleIdentifier"):
        fail(msgs, "CFBundleIdentifier vazio")
    if plist.get("CFBundleSupportedPlatforms") != ["iPhoneOS"]:
        fail(msgs, "CFBundleSupportedPlatforms=%r, esperado ['iPhoneOS']" % plist.get("CFBundleSupportedPlatforms"))
    if not plist.get("UIFileSharingEnabled"):
        fail(msgs, "UIFileSharingEnabled ausente (o app nao ve Documents no Files)")

    exe_name = plist.get("CFBundleExecutable")
    if not exe_name:
        fail(msgs, "CFBundleExecutable ausente")
        print_report(ok, msgs)
        return 1
    info = z.getinfo("%s/%s" % (app, exe_name))
    mode = (info.external_attr >> 16) & 0o777
    if mode & 0o111 != 0o111:
        fail(msgs, "executavel sem bit de execucao (modo %o)" % mode)
    data = z.read(info)
    ok.append("executavel %s: %d bytes (%.1f MB), modo %o" % (exe_name, len(data), len(data) / 1048576.0, mode))
    if a.min_bytes and len(data) < a.min_bytes:
        fail(msgs, "executavel %d bytes < minimo %d: build sem o jogo" % (len(data), a.min_bytes))

    before = []
    mi = macho_info(data, before)
    msgs.extend(before)
    if mi and not before:
        ok.append("Mach-O arm64, platform=%s, minos=%s" % (mi["platform"], mi["minos"]))

    needles = [b"dmsh", b"nvn", b"fixups"]
    found = [n.decode() for n in needles if n in data]
    if not found:
        fail(msgs, "nenhum simbolo do host (dmsh/nvn/fixups) no binario: provavel casca")
    else:
        ok.append("simbolos do host encontrados: %s" % ", ".join(found))

    names = z.namelist()
    romfs = [n for n in names if "romfs" in n.lower()]
    shaders = [n for n in names if "/msl/" in n.lower() or n.lower().endswith(".metallib")]
    if romfs:
        ok.append("RomFS dentro do IPA: %d entradas" % len(romfs))
    else:
        ok.append("RomFS fora do IPA (--romfs separate): copiar com scripts/push_romfs.sh")
    if shaders:
        ok.append("bibliotecas de shader no IPA: %d entradas" % len(shaders))
    else:
        fail(msgs, "sem bibliotecas de shader (/msl/ ou .metallib): o jogo nao desenha")

    print("sha256  %s" % h.hexdigest())
    print("arquivo %s (%.2f GB)" % (a.ipa, _filesize(a.ipa)))
    print_report(ok, msgs)
    return 0 if not msgs else 1


def _filesize(path):
    import os
    return os.path.getsize(path) / (1024 ** 3)


def print_report(ok, msgs):
    for line in ok:
        print("  ok   %s" % line)
    for line in msgs:
        print("  FAIL %s" % line)
    print("RESULTADO: %s" % ("PASSOU" if not msgs else "%d falha(s)" % len(msgs)))


if __name__ == "__main__":
    sys.exit(main())
