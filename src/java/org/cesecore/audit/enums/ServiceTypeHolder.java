package org.cesecore.audit.enums;

/**
 * Simple implementation of ServiceType that holds the identifier.
 * 
 * Based on CESeCore version:
 *      ServiceTypeHolder.java 919 2011-07-01 11:19:33Z filiper
 * 
 * @version $Id$
 */
public class ServiceTypeHolder implements ServiceType {

    private static final long serialVersionUID = 1L;

    private final String value;
    
    public ServiceTypeHolder(final String value) {
        this.value = value;
    }
    
    @Override
    public String toString() {
        return value;
    }
    
    @Override
    public boolean equals(final ServiceType value) {
        if (value == null) {
            return false;
        }
        return this.value.toString().equals(value);
    }
}
