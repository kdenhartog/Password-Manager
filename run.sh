#!/bin/bash

javac -classpath bcprov-jdk15on-156.jar PassManager.java SecurityFunction.java
java -classpath bcprov-jdk15on-156.jar:. PassManager
