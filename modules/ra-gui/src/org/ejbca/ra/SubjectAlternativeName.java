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
package org.ejbca.ra;

import java.util.ArrayList;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/**
 * Contains Subject Alternative Name attributes
 * @version $Id$
 *
 */
public class SubjectAlternativeName extends RaAbstractDn {

    public SubjectAlternativeName(final EndEntityProfile endEntityProfile) {
        super(endEntityProfile);
    }
    
    public SubjectAlternativeName(final EndEntityProfile endEntityProfile, final String subjectAlternativeName) {
        super(endEntityProfile, subjectAlternativeName);
    }

    @Override
    protected int getAbstractDnFieldExtractorType() {
        return DNFieldExtractor.TYPE_SUBJECTALTNAME;
    }

    @Override
    protected ArrayList<String> getAbstractDnFields() {
        return DnComponents.getAltNameFields();
    }

    @Override
    protected String reorder(String dnBeforeReordering) {
        return dnBeforeReordering; //No reordering for Subject Alternative Name
    }
}