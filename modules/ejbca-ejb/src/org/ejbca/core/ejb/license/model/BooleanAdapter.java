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

import jakarta.xml.bind.annotation.adapters.XmlAdapter;

public class BooleanAdapter extends XmlAdapter<String, Boolean> {
    @Override
    public Boolean unmarshal(String v) throws Exception {
        if (v == null) {
            return null;
        }
        return "True".equals(v);
    }

    @Override
    public String marshal(Boolean v) throws Exception {
        if (v == null) {
            return null;
        }
        if (v) {
            return "True";
        } else {
            return "False";
        }
    }
}
