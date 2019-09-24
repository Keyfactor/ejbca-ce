/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token;

import java.io.Serializable;

/**
 * Representation of a KeyPair in a CryptoToken. Does not contain the actual keys.
 * 
 * @version $Id$
 */
public class KeyPairInfo implements Serializable, Comparable<KeyPairInfo> {

    private static final long serialVersionUID = 1L;

    private String alias = "";
    private String keyAlgorithm;
    private String keySpecification;
    private String subjectKeyID = "";

    public KeyPairInfo(final String alias, final String keyAlgorithm, final String keySpecification, final String subjectKeyID) {
        this.alias = alias;
        this.keyAlgorithm = keyAlgorithm;
        this.keySpecification = keySpecification;
        this.subjectKeyID = subjectKeyID;
    }

    public String getAlias() { return alias; }
    public void setAlias(String alias) { this.alias = alias; }
    public String getKeyAlgorithm() { return keyAlgorithm; }
    public void setKeyAlgorithm(String keyAlgorithm) { this.keyAlgorithm = keyAlgorithm; }
    public String getKeySpecification() { return keySpecification; }
    public void setKeySpecification(String keySpecification) { this.keySpecification = keySpecification; }
    public String getSubjectKeyID() { return subjectKeyID; }
    public void setSubjectKeyID(String subjectKeyID) { this.subjectKeyID = subjectKeyID; }

    @Override
    public int compareTo(final KeyPairInfo o) {
        int c;
        
        c = alias.compareTo(o.alias);
        if (c != 0) { return c; }
        
        // There shouldn't be multiple aliases with the same name, but we compare the other fields just to be sure.
        c = keyAlgorithm.compareTo(o.keyAlgorithm);
        if (c != 0) { return c; }
        c = keySpecification.compareTo(o.keySpecification);
        if (c != 0) { return c; }
        
        return 0;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((alias == null) ? 0 : alias.hashCode());
        result = prime * result + ((keyAlgorithm == null) ? 0 : keyAlgorithm.hashCode());
        result = prime * result + ((keySpecification == null) ? 0 : keySpecification.hashCode());
        result = prime * result + ((subjectKeyID == null) ? 0 : subjectKeyID.hashCode());
        return result;
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
        KeyPairInfo other = (KeyPairInfo) obj;
        if (alias == null) {
            if (other.alias != null) {
                return false;
            }
        } else if (!alias.equals(other.alias)) {
            return false;
        }
        if (keyAlgorithm == null) {
            if (other.keyAlgorithm != null) {
                return false;
            }
        } else if (!keyAlgorithm.equals(other.keyAlgorithm)) {
            return false;
        }
        if (keySpecification == null) {
            if (other.keySpecification != null) {
                return false;
            }
        } else if (!keySpecification.equals(other.keySpecification)) {
            return false;
        }
        if (subjectKeyID == null) {
            if (other.subjectKeyID != null) {
                return false;
            }
        } else if (!subjectKeyID.equals(other.subjectKeyID)) {
            return false;
        }
        return true;
    }

}
