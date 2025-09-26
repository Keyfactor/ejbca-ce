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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;

public class FileUtil {

    public static File getPwd() throws IOException {
        return new File(".").getCanonicalFile();
    }

    public static File getResourceAsFile(String name) throws IOException {
        System.out.println("*** name = " + name);
        System.out.println("*** pwd  = " + getPwd());
        URL url = FileUtil.class.getClassLoader().getResource(name);
        if (url == null) {
            throw new FileNotFoundException(name);
        }
        File file = new File(url.getFile()).getCanonicalFile();
        if (!file.exists()) {
            throw new FileNotFoundException(name);
        }
        return file;
    }

}
