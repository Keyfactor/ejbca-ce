/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class FileUtil {

    private static void appendFiles(File dirOrFile, String name, List<File> files) {
        if (dirOrFile.isFile()) {
            if (dirOrFile.getName().equals(name)) {
                files.add(dirOrFile);
            }
        }
        else {
            for (File file : dirOrFile.listFiles()) {
                appendFiles(file, name, files);
            }
        }
    }

    public static List<File> findAllFiles(File dir, String name) {
        File file = new File(dir, name);
        List<File> files = new ArrayList<>();
        appendFiles(file.getParentFile(), file.getName(), files);
        return files;
    }

    private static byte[] readFile(File file) throws IOException {
        return new FileInputStream(file).readAllBytes();
    }

    private static boolean isIdentical(File file1, File file2) throws IOException {
        var array1 = readFile(file1);
        var array2 = readFile(file2);
        if (array1.length != array2.length) {
            return false;
        }
        for (int i = 0; i < array1.length; i++) {
            if (array1[i] != array2[i]) {
                return false;
            }
        }
        return true;
    }

    public static String getCanonicalPath(File file)  {
        try {
            return file.getCanonicalPath();
        } catch (IOException e) {
            throw new IllegalStateException("Could not get canonical path of: "+file.getAbsolutePath(), e);
        }
    }

    public static File getUniqueFile(String name) throws IOException {
        return getUniqueFile(name, new File("."));
    }

    public static File getUniqueFile(String name, File dir) throws IOException {
        List<File> files = findAllFiles(dir, name);
        String fullDirName = getCanonicalPath(dir);
        if (files.size() == 0) {
            throw new IOException("Cannot find any file named \""+name+"\" in directory \""+fullDirName+"\".");
        }
        for (int i=1; i<files.size(); i++) {
            if (!isIdentical(files.get(0), files.get(i))) {
                String name1 = getCanonicalPath(files.get(0));
                String name2 = getCanonicalPath(files.get(i));
                throw new IOException("Files \""+name1+"\" and \""+name2+"\" are not identical.");
            }
        }
        return files.get(0);
    }

    public static String getUniqueFilePath(String name) throws IOException {
        return getUniqueFilePath(name, new File("."));
    }

    public static String getUniqueFilePath(String name, File dir) throws IOException {
        return getCanonicalPath(getUniqueFile(name, dir));
    }

}
