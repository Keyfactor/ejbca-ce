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
 package org.cesecore;

 /**
  * Must be used only with wrapping exceptions that still don't extends CesecoreException but they should do to
  * reduce API signatures and later be refactored safely one by one.
  * @version $Id$
  */
public class NonHandledCesecoreException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    
    public NonHandledCesecoreException(Throwable cause){
        super(cause);
    }
    
    public NonHandledCesecoreException(String message, Throwable cause){
        super(message, cause);
    }
}
