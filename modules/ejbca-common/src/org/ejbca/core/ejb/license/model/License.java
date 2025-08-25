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

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.PastOrPresent;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import java.time.ZonedDateTime;

@XmlAccessorType(XmlAccessType.FIELD)

public class License {
    
    public static final String LICENSE_EXPIRED = "LICENSE_EXPIRED";
    
    @XmlAttribute
    @NotBlank
    private String id;

    @XmlAttribute
    @XmlJavaTypeAdapter(ZoneDateTimeAdapter.class)
    @NotNull
    @PastOrPresent
    private ZonedDateTime issuedDate;

    @XmlAttribute
    @XmlJavaTypeAdapter(ZoneDateTimeAdapter.class)
    @NotNull
    @Future(message = LICENSE_EXPIRED)
    private ZonedDateTime expirationDate;

    @XmlAttribute
    @NotBlank
    private String issuerName;

    public ZonedDateTime getExpirationDate() {
        return expirationDate;
    }
        
}
