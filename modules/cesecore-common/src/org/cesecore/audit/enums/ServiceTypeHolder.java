package org.cesecore.audit.enums;

/**
 * Simple implementation of ServiceType that holds the identifier.
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
    public boolean equals(final ServiceType otherValue) {
        if (otherValue == null) {
            return false;
        }
        return value.equals(otherValue.toString());
    }
}
