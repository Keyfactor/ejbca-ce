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
package org.ejbca.core.ejb.authentication.cli;

import jakarta.ejb.Remote;

/**
 * Assists with some actions in CliAuthenticationSystemTest
 */
@Remote
public interface CliAuthenticationSystemTestHelperSessionRemote {
  
    String USERNAME = "clitest";
    String PASSWORD = "clitest";
    
    void createUser(String username, String password);
    
    
    
}
