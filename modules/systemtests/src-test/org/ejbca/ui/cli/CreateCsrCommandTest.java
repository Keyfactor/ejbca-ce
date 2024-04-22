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
package org.ejbca.ui.cli;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.ejbca.ui.cli.csr.CreateCsrCommand;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 * Basic system test for the CreateCsrCommand
 * 
 *
 */
public class CreateCsrCommandTest {

    private CreateCsrCommand command = new CreateCsrCommand();

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }
    
    @Test
    public void testVanilla() throws IOException {
        Path tmpDir = Files.createTempDirectory("CreateCsrCommandTest");
        String[] args = new String[] { "--subjectdn", "CN=foo", "--keyalg", "RSA", "--keyspec", "1024", "--altkeyalg", "DILITHIUM2", "--destination", tmpDir.toFile().getAbsolutePath() };
        //Verify that the command ran without errors
        assertEquals("CreateCsrCommand executed with errors, see logs.", CommandResult.SUCCESS, command.execute(args));
       
    }
}
