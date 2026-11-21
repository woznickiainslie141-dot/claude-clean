"""Rebuild the on-device debug-shell monitor with Android SDK 35 and a JDK."""
# SPDX-License-Identifier: MIT
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile


def main():
    parser = argparse.ArgumentParser()
    sdk = Path(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", ".")))
    parser.add_argument("--platform", type=Path, default=sdk / "platforms/android-35/android.jar")
    parser.add_argument("--d8", type=Path, default=sdk / "build-tools/35.0.0/lib/d8.jar")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory() as tmp:
        temp = Path(tmp)
        def jdk(tool):
            return shutil.which(tool) or str(Path(os.environ["JAVA_HOME"]) / "bin" / tool)
        subprocess.run([jdk("javac"), "--release", "8", "-g:none", "-encoding", "UTF-8", "-classpath",
                        args.platform, "-d", temp, root / "RouteWatch.java"], check=True)
        subprocess.run([jdk("java"), "-cp", args.d8, "com.android.tools.r8.D8", "--release", "--min-api", "26",
                        "--lib", args.platform, "--output", temp, *sorted(temp.rglob("*.class"))], check=True)
        with zipfile.ZipFile(root / "route-watch.jar", "w") as jar:
            jar.writestr(zipfile.ZipInfo("classes.dex"), (temp / "classes.dex").read_bytes())


if __name__ == "__main__":
    main()
