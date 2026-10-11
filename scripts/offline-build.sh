#!/usr/bin/env bash
# ==============================================================
# Offline build & test harness (used in the development sandbox).
#
# The normal build on a student machine is:
#     mvn clean test          # compile + run the JUnit 5 suite
#     mvn javafx:run          # desktop application
#
# This script exists for environments WITHOUT Maven/javac: it
# compiles every source with the Janino compiler and runs the
# tests through a small reflective runner. It is NOT required to
# use the project.
# ==============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JAVA_HOME="${JAVA_HOME:-/home/user/tools/jdk4py-extract/jdk4py/java-runtime}"
JANINO_JARS="${JANINO_JARS:-/home/user/tools/jars/janino-3.1.9.jar:/home/user/tools/jars/commons-compiler-3.1.9.jar}"
DERBY_JARS="${DERBY_JARS:-/home/user/tools/jars/derby-10.16.1.1.jar:/home/user/tools/jars/derbyshared-10.16.1.1.jar}"
STUBS="${STUBS:-/tmp/junit-stub}"
RUNNER="${RUNNER:-/tmp/junit-stub-out}"

echo "[1/4] Compiling main sources (Janino, Java 8 target) ..."
find src/main/java -name '*.java' > /tmp/sources.txt
rm -rf tools-local/out/classes && mkdir -p tools-local/out/classes
xargs -a /tmp/sources.txt "$JAVA_HOME/bin/java" -DdefaultTargetVersion=8 \
  -cp "$JANINO_JARS" org.codehaus.commons.compiler.samples.CompilerDemo \
  -sourcepath "src/main/java:/tmp/fx-stub" -d tools-local/out/classes

echo "[2/4] Compiling tests ..."
find src/test/java -name '*.java' > /tmp/test-sources.txt
rm -rf tools-local/out/test-classes && mkdir -p tools-local/out/test-classes
xargs -a /tmp/test-sources.txt "$JAVA_HOME/bin/java" -DdefaultTargetVersion=8 \
  -cp "$JANINO_JARS" org.codehaus.commons.compiler.samples.CompilerDemo \
  -sourcepath "src/main/java:$STUBS" -d tools-local/out/test-classes

echo "[3/4] Running unit tests ..."
"$JAVA_HOME/bin/java" -cp "$RUNNER:tools-local/out/test-classes:$DERBY_JARS" StubTestRunner \
  com.medicalsecurity.crypto.CryptoEngineTest \
  com.medicalsecurity.crypto.KeyProtectorTest \
  com.medicalsecurity.crypto.PasswordHasherTest \
  com.medicalsecurity.security.PathGuardTest \
  com.medicalsecurity.security.AuthorizationTest \
  com.medicalsecurity.model.TransferStatusTest \
  com.medicalsecurity.dao.UserDaoTest \
  com.medicalsecurity.dao.TransferDaoTest \
  com.medicalsecurity.service.AuthServiceTest \
  com.medicalsecurity.service.TransferFlowTest

echo "[4/4] Running end-to-end demo ..."
"$JAVA_HOME/bin/java" -cp "tools-local/out/classes:$DERBY_JARS" \
  com.medicalsecurity.demo.HeadlessEndToEndDemo

echo "All done."
