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

package org.ejbca.core.protocol.ws.client;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.junit.Test;

/**
 * Tests RevokeCertWithMetadataCommand parameter handling.
 * 
 * @version $Id: RevokeCertWithMetadataCommandTest.java 22930 2016-03-04 14:02:35Z tarmo_r_helmes $
 */
public class RevokeCertWithMetadataCommandTest {


    @Ignore
    @Test()
    public void testRevokeCertNoMetadataParameters() throws ErrorAdminCommandException, IllegalAdminCommandException {
        String[] args = new String[3];
        args[0] = "ejbcawsracli";
        args[1] = "revokecertwithmetadata";
        args[2] = "63706289784032807";

        RevokeCertWithMetadataCommand command = new RevokeCertWithMetadataCommand(args);
        command.execute();
    }
}
