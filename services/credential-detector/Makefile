SOURCES := $(shell find src/main/java -name '*.java')
TEST_SOURCES := $(shell find src/test/java -name '*.java')

.PHONY: build test run clean

build:
	mkdir -p target/classes
	javac -Xlint:all -Werror -d target/classes $(SOURCES)

test: build
	mkdir -p target/test-classes
	javac -Xlint:all -Werror -cp target/classes -d target/test-classes $(TEST_SOURCES)
	java -ea -cp target/classes:target/test-classes io.attestguard.detector.DetectorEngineTest

run: build
	java -cp target/classes io.attestguard.detector.Main

clean:
	rm -rf target
