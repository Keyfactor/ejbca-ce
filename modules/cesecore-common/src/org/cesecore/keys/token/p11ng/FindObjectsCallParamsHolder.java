/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

import java.util.Arrays;
import java.util.Objects;

/**
 * Holder for parameters of findObjects method HSM calls with respect to P11NG provider.
 * 
 * @author Vinay Singh
 * @version $Id$
 */
public class FindObjectsCallParamsHolder {

    private final String ckaClassName;
    private final String paramName;
    private final String ckaLabel;
    private final byte[] ckaId;
    private final byte[] ckaSubject;

    public FindObjectsCallParamsHolder(String ckaClassName, String paramName, String ckaLabel) {
        this.ckaClassName = ckaClassName;
        this.paramName = paramName;
        this.ckaLabel = ckaLabel;
        this.ckaId = null;
        this.ckaSubject = null;
    }

    public FindObjectsCallParamsHolder(String ckaClassName, String paramName, byte[] ckaId, byte[] ckaSubject) {
        this.ckaClassName = ckaClassName;
        this.paramName = paramName;
        this.ckaId = ckaId;
        this.ckaSubject = ckaSubject;
        this.ckaLabel = null;
    }

    public String getCkaLabel() {
        return ckaLabel;
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + Objects.hashCode(this.ckaClassName);
        hash = 53 * hash + Objects.hashCode(this.paramName);
        hash = 53 * hash + Objects.hashCode(this.ckaLabel);
        hash = 53 * hash + Arrays.hashCode(this.ckaId);
        hash = 53 * hash + Arrays.hashCode(this.ckaSubject);
        return hash;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final FindObjectsCallParamsHolder other = (FindObjectsCallParamsHolder) obj;
        if (!Objects.equals(this.ckaClassName, other.ckaClassName)) {
            return false;
        }
        if (!Objects.equals(this.paramName, other.paramName)) {
            return false;
        }
        if (!Objects.equals(this.ckaLabel, other.ckaLabel)) {
            return false;
        }
        if (!Arrays.equals(this.ckaId, other.ckaId)) {
            return false;
        }
        if (!Arrays.equals(this.ckaSubject, other.ckaSubject)) {
            return false;
        }
        return true;
    }

    @Override
    public String toString() {
        return "FindObjectsCallParamsHolder{" + "ckaClassName=" + ckaClassName + ", paramName=" + paramName + ", ckaLabel=" + ckaLabel + ", ckaId=" + ckaId + ", ckaSubject=" + ckaSubject + '}';
    }

}
