
/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.config;

import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

/**
 * Unit tests for GlobalCesecoreConfiguration
 */

public class GlobalCesecoreConfigurationUnitTest {

    /**
     * Forbidden characters are base64 encoded in the database, so just making sure that encoding and decoding work as expected
     */
    @Test
    public void testForbiddenCharactersBase64Encoding() {
        GlobalCesecoreConfiguration globalCesecoreConfiguration = new GlobalCesecoreConfiguration();
        globalCesecoreConfiguration.setForbiddenCharacters(GlobalCesecoreConfiguration.DEFAULT_FORBIDDEN_CHARACTERS);
        assertTrue("Forbidden character list was not stored properly.", Arrays.equals(GlobalCesecoreConfiguration.DEFAULT_FORBIDDEN_CHARACTERS,
                globalCesecoreConfiguration.getForbiddenCharacters()));
    }

}
