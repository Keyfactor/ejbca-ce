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
import java.util.ArrayList;
import java.util.List;

/**
 * Search request for certificates from RA UI.
 * 
 * @version $Id$
 */
public class RaCertificateSearchRequest implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<Integer> caIds = new ArrayList<>();
    private String basicSearch = "";

    public List<Integer> getCaIds() { return caIds; }
    public void setCaIds(List<Integer> caIds) { this.caIds = caIds; }
    public String getBasicSearch() { return basicSearch; }
    public void setBasicSearch(final String basicSearch) { this.basicSearch = basicSearch; }
}
