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
package org.ejbca.core.ejb.db;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class DatabaseContentRule extends TestWatcher {

    private static final Logger log = Logger.getLogger(DatabaseContentRule.class);
    private static final DatabaseSessionRemote databaseSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(DatabaseSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    DatabaseContent databaseContent = null;

    private boolean isActive() {
        return "true".equalsIgnoreCase(System.getProperty("ejbca.databasecontent.rule", "true"));
    }

    @Override
    protected void starting(Description description) {
        if (isActive()) {
            log.info("Removing database records");
            databaseContent = databaseSessionRemote.clearTables(false);
        }
        super.starting(description);
    };

    @Override
    protected void finished(Description description) {
        if (isActive()) {
            log.info("Restoring database records");
            databaseSessionRemote.clearTables(true);
            databaseSessionRemote.restoreTables(databaseContent);
        }
        super.finished(description);
    }

}

