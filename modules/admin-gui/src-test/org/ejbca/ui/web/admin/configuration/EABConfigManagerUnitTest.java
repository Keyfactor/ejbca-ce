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
package org.ejbca.ui.web.admin.configuration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import org.ejbca.core.EjbcaException;
import org.junit.Test;

public class EABConfigManagerUnitTest {

    @Test
    public void emptyFile() throws EjbcaException {
        final Map<String, Set<String>> map = EABConfigManager.parseCsvToMap(null, null);
        assertNull("Result should be null for null input", map);
    }

    @Test
    public void defineDelimeter() throws EjbcaException {
        final byte[] bytes = ("Flowers* Rose\n" +
                "Flowers * Lily\n" +
                "Flowers* Tulip\n" +
                "Trees*Ash\n" +
                "Trees*Birch\n" +
                "Trees*Cherry\n" +
                "Flowers* Orchid\n" +
                "Trees *Maple"
        ).getBytes(StandardCharsets.UTF_8);
        final Map<String, Set<String>> map = EABConfigManager.parseCsvToMap(bytes, "\\*");
        assertEquals("Should contain 2 namespace value", 2, map.size());
        assertEquals("Flowers namespace should contain 4 values", 4, map.get("Flowers").size());
    }

    @Test
    public void duplicateAccountValue() throws EjbcaException {
        final byte[] bytes = ("Flowers, Rose\n" +
                "Flowers, Lily \n" +
                "Flowers, Tulip \n" +
                "Flowers , Tulip\n" +
                "Trees,Ash\n" +
                "Trees ,Birch\n" +
                "Trees, Cherry\n" +
                "Flowers, Orchid\n" +
                "Trees, Maple\n"
        ).getBytes(StandardCharsets.UTF_8);
        final Map<String, Set<String>> map = EABConfigManager.parseCsvToMap(bytes, null);
        assertEquals("Should contain 2 namespace value", 2, map.size());
        assertEquals("Flowers namespace should contain 4 values", 4, map.get("Flowers").size());
    }

    @Test
    public void extraColumns() throws EjbcaException {

        final byte[] bytes = ("Flowers, Rose\n" +
                "Flowers, Lily , Something\n"
        ).getBytes(StandardCharsets.UTF_8);
        Throwable throwable =  assertThrows(Throwable.class, () -> {
            EABConfigManager.parseCsvToMap(bytes, null);
        });
        assertEquals("Incorrect exception was thrown.", EjbcaException.class, throwable.getClass());
        assertEquals("Incorrect error message in exception.", "Wrong file format error in line 2", throwable.getMessage());   
    }

    @Test
    public void oneColumns() throws EjbcaException {
        final byte[] bytes = ("Flowers\n" +
                "Flowers, Lily \n"
        ).getBytes(StandardCharsets.UTF_8);
        Throwable throwable =  assertThrows(Throwable.class, () -> {
            EABConfigManager.parseCsvToMap(bytes, null);
        });
        assertEquals("Incorrect exception was thrown.", EjbcaException.class, throwable.getClass());
        assertEquals("Incorrect error message in exception.", "Wrong file format error in line 1", throwable.getMessage());   
    }

    @Test
    public void unecpectedCharactersInAccountID() throws EjbcaException {
        final byte[] bytes = ( "Flowers, Li@ly \n").getBytes(StandardCharsets.UTF_8);
        Throwable throwable =  assertThrows(Throwable.class, () -> {
            EABConfigManager.parseCsvToMap(bytes, null);
        });
        assertEquals("Incorrect exception was thrown.", EjbcaException.class, throwable.getClass());
        assertEquals("Incorrect error message in exception.", "Namespace or accountId contains characters that are not allowed in line 1", throwable.getMessage());   
    }

    @Test
    public void unecpectedCharactersInNamespace() throws EjbcaException {
        final byte[] bytes = ( "Flowers, Lily \n Flo*wers, Lily \n").getBytes(StandardCharsets.UTF_8);
        Throwable throwable =  assertThrows(Throwable.class, () -> {
            EABConfigManager.parseCsvToMap(bytes, null);
        });
        assertEquals("Incorrect exception was thrown.", EjbcaException.class, throwable.getClass());
        assertEquals("Incorrect error message in exception.", "Namespace or accountId contains characters that are not allowed in line 2", throwable.getMessage());   
    }
}
