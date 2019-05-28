/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services;

/**
 * @version $Id$
 *
 */
public class ServiceExecutionResult {

    public enum Result {
        SUCCESS("Success"), NO_ACTION("No action"), FAILURE("Failure");
        
        private final String output;
        
        private Result(final String output) {
            this.output = output;
        }

        public String getOutput() {
            return output;
        }

    }

    private final Result result;
    private final String msg;

    /**
     * 
     */
    public ServiceExecutionResult(final Result result, final String msg) {
        this.result = result;
        this.msg = msg;
    }

    public Result getResult() {
        return result;
    }

    public String getMessage() {
        return msg;
    }

}
