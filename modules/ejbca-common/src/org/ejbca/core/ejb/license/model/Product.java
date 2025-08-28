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

import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlAttribute;
import jakarta.xml.bind.annotation.XmlElement;
import jakarta.xml.bind.annotation.XmlElementWrapper;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Pattern.Flag;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
public class Product {
    @XmlAttribute
    @NotBlank
    private String id;

    @XmlAttribute
    @NotBlank
    @Pattern(flags = Flag.CASE_INSENSITIVE, regexp = ".*ejbca.*")
    private String displayName;

    @XmlAttribute
    private Integer majorRev;

    @XmlAttribute
    private Integer minorRev;

    @XmlElementWrapper(name = "Features")
    @XmlElement(name = "Feature")
    @NotEmpty
    private List<Feature> features;
}
