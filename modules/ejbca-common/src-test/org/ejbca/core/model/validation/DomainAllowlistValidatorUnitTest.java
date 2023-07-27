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
package org.ejbca.core.model.validation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

public class DomainAllowlistValidatorUnitTest {
    
    private static final Logger log = Logger.getLogger(DomainAllowlistValidatorUnitTest.class);

    private static final byte[] WHITELIST = ("permit.com\n" + 
            "permit.example.com\n" + 
            "#good.example.com\n" + 
            "permit2.example.com # this is a comment\n" + 
            "    permit3.example.com     \n" + 
            "permit4.example.com# comment\n" + 
            "permit5.*.example.com\n" +
            "*.permit6.*.example.com\n" +
            "permit7.example.*\n" +
            "permit8.partial*.com\n" +
            "*.*.permit9.example.com\n" +
            "\n").getBytes(StandardCharsets.UTF_8);

    private static final byte[] MALFORMED_WHITELIST = ("# some line\n" + 
            "detta-behöver-punycodas\n" + // line that is not punycoded
            "\n").getBytes(StandardCharsets.UTF_8);
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    @Test
    public void parseAllowlistFile() throws DomainListFileException {
        final DomainAllowlistValidator validator = new DomainAllowlistValidator();
        validator.changeWhitelist(WHITELIST);
        final Collection<String> whitelist = validator.getWhitelist();
        log.debug("Result after parsing: " + whitelist);
        String[] allowedDomains = new String[] {"permit.com", "permit.example.com", "permit2.example.com", 
                                         "permit3.example.com", "permit4.example.com", 
                                         "permit5\\..*\\.example\\.com", ".*\\.permit6\\..*\\.example\\.com",
                                         "permit7\\.example\\..*", "permit8\\.partial.*\\.com"};
        assertEquals("Wrong number of entries in parsed blacklist.", 10, whitelist.size());
        for(String domain: allowedDomains)
            assertTrue("Should contain " + domain, whitelist.contains(domain));
        
        final String WHITELIST_SHA256 = "757a9393b71d52daac6b645cbb47575e6266c5c360c8589acaf4f3daa3bd9732";
        assertEquals("Wrong SHA-256 hash.", WHITELIST_SHA256, validator.getWhitelistSha256());
        assertNotNull("Upload date should be set", validator.getWhitelistDate());
    }

    @Test
    public void parseMalformedAllowlistFile() {
        final DomainAllowlistValidator validator = new DomainAllowlistValidator();
        try {
            validator.changeWhitelist(MALFORMED_WHITELIST);
            fail("Should throw");
        } catch (DomainListFileException exception) {
            assertTrue(exception.getMessage().startsWith("Invalid syntax of domain at line 2."));
        }    
    }
    
    @Test
    public void matchAllowedDomains() throws DomainListFileException {
        DomainAllowlistValidator validator = new DomainAllowlistValidator();
        validator.changeWhitelist(WHITELIST);
        String[] expectedAllowedDomains = new String[] {"permit.com", "permit.example.com", "permit2.example.com", 
                "permit3.example.com", "permit4.example.com", 
                "permit5.abc.example.com", "abc.permit6.def.example.com", "permit7.example.de",
                "permit8.partialxyz.com", "permit5.*.example.com", "*.permit6.*.example.com",
                "permit7.example.*", "permit8.partial*.com", "abc.permit6.*.example.com", "*.permit6.def.example.com",
                "xx.yy.permit9.example.com"
                };
        List<String> failures = new ArrayList<String>();
        Entry<Boolean,List<String>> result = null;
        for(String domain: expectedAllowedDomains) {
            result = validator.validate(null, domain);
            if(!result.getKey())
                failures.add(result.getValue().toString());
        }
        assertTrue("Not allowed domains: " + failures.toString(), failures.isEmpty());
    }
    
    @Test
    public void matchAllowedDomainsNegative() throws DomainListFileException {
        DomainAllowlistValidator validator = new DomainAllowlistValidator();
        validator.changeWhitelist(WHITELIST);
        String[] expectedDisallowedDomains = new String[] {"permit1.com", "permit.example1.com", ".permit2.example.com", 
                "permit3..example.com", "permit4.example.com1", 
                "permit5.example.com", "permit6.def.example.com", "permit6.example.com", "permit7.example",
                "xx.permit9.example.com"};
        List<String> failures = new ArrayList<String>();
        Entry<Boolean,List<String>> result = null;
        for(String domain: expectedDisallowedDomains) {
            result = validator.validate(null, domain);
            if(result.getKey())
                failures.add(result.getValue().toString());
        }
        assertTrue("Allowed domains: " + failures.toString(), failures.isEmpty());
    }

}
