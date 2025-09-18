package org.ejbca.core.ejb.license.model;

/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.UUID;

public class LicenseTestUtil {
    
    public static LicenseData createSampleLicense(ZonedDateTime expiryDate) {
     
        License license = new License();
        license.setId(UUID.randomUUID().toString());
        license.setIssuerName("keyfactor");
        license.setExpirationDate(expiryDate);
        license.setIssuedDate(ZonedDateTime.of(2024, 12, 1, 5, 4, 3, 0, ZoneId.of("UTC")));
        
        Customer customer = new Customer();
        customer.setName("some customer");
        customer.setCrmId(UUID.randomUUID().toString());
        
        Product ejbca = new Product();
        ejbca.setDisplayName("ejbca container");
        ejbca.setId(UUID.randomUUID().toString());
        ejbca.setMajorRev(9);
        ejbca.setMinorRev(4);
        
        Feature feature = new Feature();
        feature.setDisplayName("core functionality");
        feature.setEnabled(true);
        feature.setId(UUID.randomUUID().toString());
        ejbca.setFeatures(List.of(feature));
        
        LicenseData licenseData = new LicenseData();
        licenseData.setLicense(license);
        licenseData.setCustomer(customer);
        licenseData.setProducts(List.of(ejbca));
        
        return licenseData;
    }

}
