package org.ejbca.core.protocol.ws.client;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.junit.Ignore;
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
        args[2] = "CN=CA1";

        RevokeCertWithMetadataCommand command = new RevokeCertWithMetadataCommand(args);
        command.execute();
    }
}
