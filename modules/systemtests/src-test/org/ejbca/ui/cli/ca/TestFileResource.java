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
package org.ejbca.ui.cli.ca;

import java.io.File;
import java.net.URL;

// TODO ECA-8963: Extract into a separate module ejbca-unittest, as it is common utility class that can be reused.
/**
 * This is a help class to locate an input file for a test from classpath.
 *
 * @version $Id$
 */
public class TestFileResource {

    private String fileName;
    private File file;

    public TestFileResource(final String fileName) {
        this.fileName = fileName;
        final URL fileUrl = getClass().getClassLoader().getResource(fileName);
        if(fileUrl == null) {
            throw new RuntimeException("Cannot locate file [" + fileName + "] in classpath.");
        }
        this.file = new File(fileUrl.getFile());
    }

    public File getFile() {
        return file;
    }

    public String getFileName() {
        return fileName;
    }

}
