package org.ejbca.webtest.utils;

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
