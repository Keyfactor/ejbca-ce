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
package org.cesecore.util;

/**
 * Thrown when there's too much data, e.g. in a stream when using FileTools.streamCopyWithLimit
 * 
 * @version $Id$
 */
public class StreamSizeLimitExceededException extends Exception {

    private static final long serialVersionUID = 1L;

    public StreamSizeLimitExceededException() {
        super();
    }
    
    public StreamSizeLimitExceededException(String message) {
        super(message);
    }

    public StreamSizeLimitExceededException(String message, Throwable cause) {
        super(message, cause);
    }

    public StreamSizeLimitExceededException(Throwable cause) {
        super(cause);
    }
    
}
