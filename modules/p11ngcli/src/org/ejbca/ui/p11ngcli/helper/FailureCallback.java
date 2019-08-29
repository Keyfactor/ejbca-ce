
package org.ejbca.ui.p11ngcli.helper;

/**
 * 
 * @version $Id$
 *
 */
public interface FailureCallback {
    /**
     * Called from different threads when a failure has happened.
     * @param thread The source thread of the failure
     * @param message A descriptive message of the failure
     */
    void failed(OperationsThread thread, String message);
}
