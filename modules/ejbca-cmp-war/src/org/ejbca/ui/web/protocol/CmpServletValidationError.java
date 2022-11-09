/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.protocol;

import org.ejbca.core.EjbcaException;

public class CmpServletValidationError extends EjbcaException {

    public CmpServletValidationError(String message) {
        super(message);
    }
}
