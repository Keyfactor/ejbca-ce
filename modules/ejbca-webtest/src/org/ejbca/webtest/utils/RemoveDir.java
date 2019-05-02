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
package org.ejbca.webtest.utils;

/**
 * Helper class used to remove an existing directory.
 *
 * @version $Id: RemoveDir.java 32091 2019-05-02 12:59:46Z margaret_d_thomas $
 *
 */
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;

import org.apache.log4j.Logger;

public class RemoveDir {

    private static final Logger log = Logger.getLogger(RemoveDir.class);

    private Path path;

    public RemoveDir(String sPath) {
        this.path = Paths.get(sPath);
    }

    /**
     * Remove list of files in directory and the directory itself.
     * Logs an info message, but does not throw exception, if the directory does not exist.
     */
    public void deleteDirectoryStream() {
        try {
            Files.walk(path)
                    .sorted(Comparator.reverseOrder())
                    .map(Path::toFile)
                    .forEach(File::delete);
        } catch (IOException e) {
            log.info("Failed to remove directory " + path);
        }
    }
}
