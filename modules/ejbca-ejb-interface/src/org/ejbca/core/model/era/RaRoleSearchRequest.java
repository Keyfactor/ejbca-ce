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
package org.ejbca.core.model.era;

import java.io.Serializable;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Search request for role from RA UI.
 * 
 * @version $Id$
 */
public class RaRoleSearchRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private String genericSearchString = "";

    /** Default constructor */
    public RaRoleSearchRequest() {}
    
    /** Copy constructor */
    public RaRoleSearchRequest(final RaRoleSearchRequest request) {
        genericSearchString = request.genericSearchString;
    }

    public String getGenericSearchString() {
        return genericSearchString;
    }

    public void setGenericSearchString(final String genericSearchString) {
        this.genericSearchString = genericSearchString;
    }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }
    
    @Override
    public boolean equals(final Object other) {
        return EqualsBuilder.reflectionEquals(this, other);
    }

}
