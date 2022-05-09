/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng.provider;

/**
 *
 */
public class NJI11Session {

    private final long id;

    private boolean findObjectsStarted;
    private boolean signStarted;

    public NJI11Session(long id) {
        this.id = id;
    }

    public long getId() {
        return id;
    }

    protected void markOperationFindObjectsStarted() {
        this.findObjectsStarted = true;
    }

    protected void markOperationFindObjectsFinished() {
        this.findObjectsStarted = false;
    }

    protected void markOperationSignStarted() {
        this.signStarted = true;
    }

    protected void markOperationSignFinished() {
        this.signStarted = false;
    }

    public boolean isOperationFindObjectsStarted() {
        return findObjectsStarted;
    }

    public boolean isOperationSignStarted() {
        return signStarted;
    }

    public boolean hasOperationsActive() {
        return findObjectsStarted || signStarted;
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 37 * hash + (int) (this.id ^ (this.id >>> 32));
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
        final NJI11Session other = (NJI11Session) obj;
        return this.id == other.id;
    }

    @Override
    public String toString() {
        return "NJI11Session{" + id + "}";
    }

}
