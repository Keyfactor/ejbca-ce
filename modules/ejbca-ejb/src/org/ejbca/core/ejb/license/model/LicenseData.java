/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.license.model;

import jakarta.validation.Valid;
import jakarta.xml.bind.annotation.*;
import java.util.List;

@XmlRootElement(name = "LicenseData")
@XmlAccessorType(XmlAccessType.FIELD)
public class LicenseData {
    @XmlElement(name = "License")
    @Valid
    private License license;

    @XmlElement(name = "Customer")
    @Valid
    private Customer customer;

    @XmlElementWrapper(name = "Products")
    @XmlElement(name = "Product")
    @Valid
    private List<Product> products;

    public License getLicense() {
        return license;
    }    

}
