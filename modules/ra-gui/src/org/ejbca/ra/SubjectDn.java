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
import java.util.List;

import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile.Field;

/**
 * Contains SubjectDN attributes
 * @version $Id$
 *
 */
public class SubjectDn {

    private List<EndEntityProfile.FieldInstance> fieldInstances;

    public SubjectDn(EndEntityProfile endEntityProfile) {
        fieldInstances = new ArrayList<EndEntityProfile.FieldInstance>();
        for (String key : DnComponents.getProfilenameIdMap().keySet()) {
            Field field = endEntityProfile.new Field(key);
            for (EndEntityProfile.FieldInstance fieldInstance : field.getInstances()) {
                fieldInstances.add(fieldInstance);
            }
        }
    }

    public List<EndEntityProfile.FieldInstance> getFieldInstances() {
        return fieldInstances;
    }

    public void setFieldInstances(List<EndEntityProfile.FieldInstance> fieldInstances) {
        this.fieldInstances = fieldInstances;
    }

    @Override
    public String toString() {
        if (fieldInstances == null) {
            return "";
        }

        return "";//TODO
    }

}
