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

import java.util.List;

import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;

/**
 * Represents two "interfaces": list (needed for JSF) and map interface
 * for the subject DN fields of the specified end entity profile.
 * 
 *
 */
public class SubjectDn extends RaAbstractDn{

    public SubjectDn(final EndEntityProfile endEntityProfile) {
        super(endEntityProfile);
    }
    public SubjectDn(final EndEntityProfile endEntityProfile, final String subjectDn) {
        super(endEntityProfile, subjectDn);
    }

    @Override
    protected int getAbstractDnFieldExtractorType() {
        return DNFieldExtractor.TYPE_SUBJECTDN;
    }

    @Override
    protected List<String> getAbstractDnFields() {
        return DnComponents.getDnProfileFields();
    }

    @Override
    protected String reorder(String dnBeforeReordering) {
        return CertTools.stringToBcX500Name(dnBeforeReordering, nameStyle, ldapOrder).toString();
    }
}
