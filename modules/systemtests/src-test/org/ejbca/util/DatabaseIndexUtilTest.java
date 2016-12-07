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
package org.ejbca.util;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.util.DatabaseIndexUtil.DatabaseIndex;
import org.junit.Test;

/**
 * Sanity check of utility class used for best effort detection of database indexes.
 * 
 * @version $Id$
 */
public class DatabaseIndexUtilTest {

    private static final Logger log = Logger.getLogger(DatabaseIndexUtilTest.class);
    private final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Test
    public void testIndexReadFromCertificateData() {
        final String TABLENAME_CERTIFICATEDATA = "CertificateData";
        final List<DatabaseIndex> databaseIndexes = internalCertStoreSession.getDatabaseIndexFromTable(TABLENAME_CERTIFICATEDATA, false);
        final String errorMsg = "DatabaseIndexUtil is not working properly on this platform. No index detected on " + TABLENAME_CERTIFICATEDATA + ".";
        assertNotNull(errorMsg, databaseIndexes); // SQLException from the utility class
        assertFalse(errorMsg, databaseIndexes.isEmpty());
        log.info("DatabaseIndexUtil was able to read the following indexes from " + TABLENAME_CERTIFICATEDATA);
        for (final DatabaseIndex databaseIndex : databaseIndexes) {
            log.info(" " + databaseIndex.getIndexName() + " spanning " + Arrays.toString(databaseIndex.getColumnNames().toArray()) + " unique="+databaseIndex.isUnique());
        }
    }
}
