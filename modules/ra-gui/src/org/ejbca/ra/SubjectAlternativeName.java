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

import com.keyfactor.util.certificate.DnComponents;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import java.util.List;

/**
 * Contains Subject Alternative Name attributes
 *
 */
public class SubjectAlternativeName extends RaAbstractDn {

    private static final long serialVersionUID = -6607540051580876349L;

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
    protected List<String> getAbstractDnFields() {
        return DnComponents.getAltNameFields();
    }

    @Override
    protected String reorder(String dnBeforeReordering) {
        return dnBeforeReordering; //No reordering for Subject Alternative Name
    }
}