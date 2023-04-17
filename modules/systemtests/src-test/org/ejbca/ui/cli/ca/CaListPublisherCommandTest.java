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
package org.ejbca.ui.cli.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 * @version $Id$
 *
 */
public class CaListPublisherCommandTest {

    private CaListPublishersCommand caListPublishersCommand;

    @Before
    public void setUp() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        caListPublishersCommand = new CaListPublishersCommand();
    }

    @Test
    public void testSanity() {
        try {
            assertEquals("CA listpublishers command is broken.", CommandResult.SUCCESS, caListPublishersCommand.execute());
        } catch (Exception e) {
            fail("CA listpublishers command is broken: " + e.getMessage());
        }
    }
}
