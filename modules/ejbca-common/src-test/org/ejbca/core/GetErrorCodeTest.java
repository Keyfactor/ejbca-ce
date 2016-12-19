/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core;


import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Tests the static EjbcaException.getErrorCode(Throwable). Although it is placed in the EjbcaException
 * this static method can be invoked for every other Throwable. Result from this method can determine
 * how the purging of the exception message and stacktrace can be done over peers. 
 * See PeerRaSerialization.SerializationExceptionHolder for more details about purging the possible
 * sensitive information with Exceptions over peers
 * 
 * @version $Id$
 */
public class GetErrorCodeTest {

	@Test
    public void testEjbcaExceptionDefaultConstructor() {
        assertNull("EjbcaException.getErrorCode of the EjbcaException() is not null", EjbcaException.getErrorCode(new EjbcaException()));
	}
	
	@Test
    public void testEjbcaExceptionMessageConstructor() {
        assertNull("EjbcaException.getErrorCode of the EjbcaException(String message) is not null", EjbcaException.getErrorCode(new EjbcaException("Exception message...")));
    }
	
	@Test
    public void testEjbcaExceptionErrorCodeConstructor() {
        assertEquals("EjbcaException.getErrorCode of the EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS) is not ErrorCode.APPROVAL_ALREADY_EXISTS",
                EjbcaException.getErrorCode(new EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS)), ErrorCode.APPROVAL_ALREADY_EXISTS);
    }

    @Test
    public void testCesecoreExceptionDefaultConstructor() {
        assertNull("EjbcaException.getErrorCode of the CesecoreException() is not null", EjbcaException.getErrorCode(new CesecoreException()));
    }

    @Test
    public void testCesecoreExceptionMessageConstructor() {
        assertNull("EjbcaException.getErrorCode of the CesecoreException(String message) is not null", EjbcaException.getErrorCode(new CesecoreException("Exception message")));
    }

    @Test
    public void testCesecoreExceptionErrorCodeConstructor() {
        assertEquals("EjbcaException.getErrorCode of the CesecoreException(ErrorCode.APPROVAL_ALREADY_EXISTS) is not ErrorCode.APPROVAL_ALREADY_EXISTS",
                EjbcaException.getErrorCode(new CesecoreException(ErrorCode.APPROVAL_ALREADY_EXISTS)), ErrorCode.APPROVAL_ALREADY_EXISTS);
    }

    @Test
    public void testEjbcaExceptionAsCauseOfAnException() {
        assertEquals("EjbcaException.getErrorCode of Exception with the cause EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS)) is not ErrorCode.APPROVAL_ALREADY_EXISTS",
                EjbcaException.getErrorCode(new Exception(new EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS))), ErrorCode.APPROVAL_ALREADY_EXISTS);
    }

    @Test
    public void testEjbcaExceptionAsCauseOfAnEjbcaException() {
        assertEquals("EjbcaException.getErrorCode of EjbcaException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST)) with the cause EjbcaException with an error code is not ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST",
                EjbcaException.getErrorCode(new EjbcaException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, new EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS))), ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST);
    }

    @Test
    public void testExceptionAsCauseOfAnEjbcaException() {
        assertEquals("EjbcaException.getErrorCode of EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS)) with the cause Exception is not ErrorCode.APPROVAL_ALREADY_EXISTS",
                EjbcaException.getErrorCode(new Exception(new EjbcaException(ErrorCode.APPROVAL_ALREADY_EXISTS))), ErrorCode.APPROVAL_ALREADY_EXISTS);
    }

    @Test
    public void testNestedExceptions() {
        assertNull("EjbcaException.getErrorCode of the Exception(new Exception()) is not null", EjbcaException.getErrorCode(new Exception(new Exception())));
    }
}
