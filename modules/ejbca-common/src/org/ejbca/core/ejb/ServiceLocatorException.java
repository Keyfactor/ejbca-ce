package org.ejbca.core.ejb;

/**
 * Exception related to resource localization.
 *
 * If such an exception is thrown it means anyway that the resource
 * lookup dramatically failed, which means that either it is a user
 * error or simply the server is totally down, so there is no point
 * in throwing a checked exception that the user won't really be
 * able to handle.
 * 
 * @version $Id$
 */
public class ServiceLocatorException extends RuntimeException {

    private static final long serialVersionUID = -4079132608707751216L;

    public ServiceLocatorException() {
        super();
    }

    public ServiceLocatorException(String message) {
        super(message);
    }

    public ServiceLocatorException(Throwable cause) {
        super(cause);
    }

    public ServiceLocatorException(String message, Throwable cause) {
        super(message, cause);
    }
}
