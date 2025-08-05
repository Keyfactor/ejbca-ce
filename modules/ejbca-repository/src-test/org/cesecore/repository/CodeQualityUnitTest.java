/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.repository;

import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.Assert.fail;

public class CodeQualityUnitTest {

    private File rootDir;
    private int rootDirLength;
    private List<File> allJavaFiles;

    @Before
    public void setUp() throws IOException {
        this.rootDir = getRootDir();
        this.rootDirLength = rootDir.getCanonicalPath().length()+1;
        this.allJavaFiles = new ArrayList<>();
        appendFiles(rootDir);
    }

    private boolean isRootDir(File file) {
        return file.isDirectory() &&
                Stream.of(file.listFiles()).anyMatch(f -> "settings.gradle.kts".equals(f.getName()));
    }

    private File getRootDir() throws IOException {
        File file = new File(".").getCanonicalFile();
        while (file != null && !isRootDir(file)) {
            file = file.getParentFile();
        }
        return file;
    }

    private boolean isUnused(final String importLine, final List<String> lines) {
        final int index = importLine.lastIndexOf(".");
        final String className = importLine.substring(index + 1).trim().replace(";", "");
        return lines.stream()
                .noneMatch(line -> line.contains(className));
    }

    private List<String> getUnusedImports(final File file) throws IOException {
        final var allLines = Files.readAllLines(file.toPath());
        final List<String> importLines = new ArrayList<>();
        for (int i = 0; i < allLines.size(); i++) {
            if (allLines.get(i).trim().startsWith("import ")) {
                importLines.add((i+1) + ". " + allLines.get(i));
            }
        }
        final var nonImportLines = allLines.stream()
                .filter(line->!line.startsWith("import "))
                .toList();
        return importLines.stream()
                .filter(importedClass -> isUnused(importedClass, nonImportLines))
                .toList();
    }

    private void appendFiles(final File dir) throws IOException {
        for (final File file : dir.listFiles()) {
            if (file.getName().startsWith(".")) {
                continue;
            }
            if (file.isDirectory()) {
                appendFiles(file);
            }
            else {
                if (file.getName().endsWith(".java")) {
                    allJavaFiles.add(file);
                }
            }
        }
    }

    @Test
    public void testUnusedImports() throws Exception {
        StringBuilder stringBuilder = new StringBuilder();
        int fileCounter = 0;
        for (final File file : allJavaFiles) {
            final var list = getUnusedImports(file);
            if (!list.isEmpty()) {
                stringBuilder.append(file.getCanonicalPath()
                        .substring(rootDirLength))
                        .append("\n");
                for (String line : list) {
                    stringBuilder.append("   ")
                            .append(line)
                            .append("\n");
                }
                fileCounter++;
            }
        }
        if (fileCounter > 0) {
            String message = "These " + fileCounter + " file(s) contains unused imports:\n\n" + stringBuilder;
            fail(message);
        }
    }

}
