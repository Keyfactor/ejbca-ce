/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng.provider;

/**
 * Representation of a PKCS#11 session.
 *
 */
public class NJI11Session {

    private final long id;

    private boolean findObjectsStarted;
    private boolean signStarted;
    private boolean closed;

    public NJI11Session(long id) {
        this.id = id;
    }

    public long getId() {
        checkOpen();
        return id;
    }

    protected void markOperationFindObjectsStarted() {
        checkOpen();
        this.findObjectsStarted = true;
    }

    protected void markOperationFindObjectsFinished() {
        checkOpen();
        this.findObjectsStarted = false;
    }

    protected void markOperationSignStarted() {
        checkOpen();
        this.signStarted = true;
    }

    protected void markOperationSignFinished() {
        checkOpen();
        this.signStarted = false;
    }

    protected void markClosed() {
        checkOpen();
        this.closed = true;
    }

    public boolean isOperationFindObjectsStarted() {
        checkOpen();
        return findObjectsStarted;
    }

    public boolean isOperationSignStarted() {
        checkOpen();
        return signStarted;
    }

    public boolean hasOperationsActive() {
        checkOpen();
        return findObjectsStarted || signStarted;
    }

    public boolean isClosed() {
        return closed;
    }

    private void checkOpen() {
        if (isClosed()) {
            throw new IllegalStateException("Session closed already: " + id);
        }
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
