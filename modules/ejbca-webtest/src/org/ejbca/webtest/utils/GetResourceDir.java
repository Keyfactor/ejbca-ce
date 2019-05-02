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
 * Helper class used the location of resource based on if running all webtests or one.
 *
 * @version $Id: GetResourceDir.java 32091 2019-05-02 12:59:46Z margaret_d_thomas $
 *
 */
import java.nio.file.Paths;

public class GetResourceDir {

    /**
     * Get the current path to the resources folder which should be determined based
     * on the ant target called, runone or webtest
     *
     * @return Folder location.
     */
    public static String getResourceFolder() {
        String cwd = Paths.get("").toAbsolutePath().toString();
        if (!cwd.contains("ejbca-webtest")) {
            return Paths.get("").toAbsolutePath().toString() + "/modules/ejbca-webtest/resources";
        } else {
            return Paths.get("").toAbsolutePath().toString() + "/resources";
        }
    }
}
