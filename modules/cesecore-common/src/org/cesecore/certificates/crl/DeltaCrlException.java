package org.cesecore.certificates.crl;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;

public class DeltaCrlException extends CesecoreException {

    private static final long serialVersionUID = -7135950339338046417L;

    /**
     * Creates a new instance without detail message.
     */
    public DeltaCrlException() {
        super(ErrorCode.DELTA_CRL_NOT_AVAILABLE);
    }

    /**
     * Constructs an instance of with the specified detail message.
     * @param msg the detail message.
     */
    public DeltaCrlException(String msg) {
        super(ErrorCode.DELTA_CRL_NOT_AVAILABLE, msg);
    }

    /**
     * Constructs an instance of with the specified cause.
     * @param e exception.
     */
    public DeltaCrlException(Exception e) {
        super(e);
    }
}
