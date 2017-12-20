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
package org.cesecore.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.List;

import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.junit.Test;

/** Tests the external process tools static helper class.
 * 
 * @version $Id: ExternalProcessToolsTest.java 25133 2017-12-14 09:20:32Z anjakobs $
 */
public class ExternalProcessToolsTest {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(ExternalProcessToolsTest.class);

    @Test
    public void test01BuildShellCommand() throws Exception {
        log.trace(">test01BuildShellCommand()");

        final String externalCommand = "help";
        final List<String> shellCommand = ExternalProcessTools.buildShellCommand(externalCommand);
        if (SystemUtils.IS_OS_WINDOWS) {
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell must be "
                    + ExternalProcessTools.WINDOWS_SHELL, shellCommand.get(0).equals(ExternalProcessTools.WINDOWS_SHELL));
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell options must be "
                    + ExternalProcessTools.WINDOWS_SHELL_OPTIONS, shellCommand.get(1).equals(ExternalProcessTools.WINDOWS_SHELL_OPTIONS));
        } else {
            // Add platforms here.
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell must be "
                    + ExternalProcessTools.WINDOWS_SHELL, shellCommand.get(0).equals(ExternalProcessTools.UNIX_SHELL));
            assertTrue("On " + ExternalProcessTools.getPlatformString() + "the platform dependend default shell options must be "
                    + ExternalProcessTools.WINDOWS_SHELL_OPTIONS, shellCommand.get(1).equals(ExternalProcessTools.UNIX_SHELL_OPTIONS));
        }
        assertEquals("The external command " + externalCommand + " must be keeped unchanged.", externalCommand, shellCommand.get(2));

        log.trace("<test01BuildShellCommand()");
    }

    @Test
    public void test02WriteTemporaryFileToDisk() throws Exception {
        log.trace(">test02WriteTemporaryFileToDisk()");

        // Write temporary file.
        final String filePrefix = getClass().getSimpleName();
        final String fileSuffix = ".tmp";
        final String content = "Read-PEM-Certificate";
        final File file = ExternalProcessTools.writeTemporaryFileToDisk(content.getBytes(), filePrefix, fileSuffix);

        // Filename must match.
        assertTrue("Filename ("+file.getName()+") must match start with filePrefix '" + filePrefix + "'and end with fileSuffix '" + fileSuffix + "'",
                file.getName().startsWith(filePrefix) && file.getName().endsWith(fileSuffix));

        // File content must match.
        final String reloadedContent = new String(FileTools.readFiletoBuffer(file.getCanonicalPath()));
        assertEquals("File contents must not have changed after reloading.", content, reloadedContent);

        // Delete file
        if (file.exists() && !file.delete()) {
            file.deleteOnExit();
        }

        log.trace("<test02WriteTemporaryFileToDisk()");
    }

    @Test
    public void test03LaunchExternalCommand() throws Exception {
        log.trace(">test03LaunchExternalCommand()");
        // ECA-6051 Todo
        log.trace("<test03LaunchExternalCommand()");
    }
}
