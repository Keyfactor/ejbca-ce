/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Logger;

import junit.framework.TestCase;

/**
 * @version $Id$
 */
public class InternalResourcesTest extends TestCase {

    protected void setUp() throws Exception {
        super.setUp();
    }

    public void testGetLocalizedMessageString() {
        InternalResources intres = InternalResourcesStub.getInstance();
        String res = intres.getLocalizedMessage("raadmin.testmsg");
        assertEquals("Test ENG", res);
        // This message will only exist in the secondary language file
        res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test SV", res);
    }

    public void testNonExistingLocalizedMessageString() {
        InternalResources intres = InternalResourcesStub.getInstance();

        String res = intres.getLocalizedMessage("raadmin.foo");
        assertEquals("raadmin.foo", res);
    }

    public void testGetLocalizedMessageStringObject() {
        InternalResources intres = InternalResourcesStub.getInstance();
        String res = intres.getLocalizedMessage("raadmin.testparams", new Long(1), new Integer(3), "hi", new Boolean(true), "bye");
        assertEquals("Test 1 3 hi true bye message 1", res);
    }

    public void testGetLocalizedMessageStringObjectWithNull() {
        InternalResources intres = InternalResourcesStub.getInstance();

        String res = intres.getLocalizedMessage("raadmin.testparams", null, new Integer(3), null, new Boolean(true), "bye");
        assertEquals("Test  3  true bye message ", res);

        res = intres.getLocalizedMessage("raadmin.testparams");
        assertEquals("Test      message ", res);
    }

    public void testMessageStringWithExtraParameter() {
        InternalResources intres = InternalResourcesStub.getInstance();
        String res = intres.getLocalizedMessage("raadmin.testmsgsv");
        assertEquals("Test SV", res);
        res = intres.getLocalizedMessage("raadmin.testmsgsv", "foo $bar \\haaaar");
        assertEquals("Test SV", res);

    }
    
    static class InternalResourcesStub extends InternalResources {

        private static final long serialVersionUID = 1L;
        private static final Logger log = Logger.getLogger(InternalResourcesStub.class);

        private InternalResourcesStub() {

            setupResources();

        }

        private void setupResources() {
            String primaryLanguage = PREFEREDINTERNALRESOURCES.toLowerCase();
            String secondaryLanguage = SECONDARYINTERNALRESOURCES.toLowerCase();

            InputStream primaryStream = null;
            InputStream secondaryStream = null;

            primaryLanguage = "en";
            secondaryLanguage = "se";
            try {
                primaryStream = new FileInputStream("src/intresources/intresources." + primaryLanguage + ".properties");
                secondaryStream = new FileInputStream("src/intresources/intresources." + secondaryLanguage + ".properties");

                try {
                    if (primaryStream != null) {
                        primaryResource.load(primaryStream);
                    } else {
                        log.error("primaryResourse == null");
                    }
                    if (secondaryStream != null) {
                        secondaryResource.load(secondaryStream);
                    } else {
                        log.error("secondaryResource == null");
                    }
                } catch (IOException e) {
                    log.error("Error reading internal resourcefile", e);
                }

            } catch (FileNotFoundException e) {
                log.error("Localization files not found", e);

            } finally {
                try {
                    if (primaryStream != null) {
                        primaryStream.close();
                    }
                    if (secondaryStream != null) {
                        secondaryStream.close();
                    }
                } catch (IOException e) {
                    log.error("Error closing internal resources language streams: ", e);
                }
            }

        }

        public static synchronized InternalResources getInstance() {
            if (instance == null) {
                instance = new InternalResourcesStub();
            }
            return instance;
        }

    }
}


