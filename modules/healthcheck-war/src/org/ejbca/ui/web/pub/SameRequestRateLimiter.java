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
package org.ejbca.ui.web.pub;

import java.util.concurrent.locks.ReentrantLock;

/**
 * Helper class for use when multiple threads a requesting something that will end up with the same result.
 * 
 * Instead of allowing each request to proceed, only the first will return a ticket where isFirst() is false.
 * Example use:
 * 
 * final static SameRequestRateLimiter<Object> srrl = new SameRequestRateLimiter<Object>();
 * ...
 * SameRequestRateLimiter<Object>.Result result = srrl.getResult();
 * if (result.isFirst()) {
 *   try {
 *     // Perform common action
 *     result.setValue(...);
 *   } catch (Throwable t) {
 *     result.setError(t);
 *   }
 * }
 * Object resultValue = result.getValue();
 * ...
 * 
 * @version $Id$
 */
public class SameRequestRateLimiter<T> {
    
    private final ReentrantLock rateLimiterLock = new ReentrantLock(false);
    private final ReentrantLock resultObjectLock = new ReentrantLock(false);
    private Result result = null;
    
    public class Result {
        private boolean isFirst = true;
        private T value;
        private Throwable throwable = null;
        
        /** @return true if the setValue should be called. */
        public boolean isFirst() {
            return isFirst;
        }
        
        /** @return the result if isFirst returns false or setValue has been called. */
        public T getValue() {
            if (isFirst) {
                // Programming/meatware problem..
                throw new RuntimeException("Current thread should have called setValue first!");
            }
            if (throwable != null) {
                throw new RuntimeException(throwable);
            }
            return value;
        }
        
        /** Store result of operation and release all pending threads */
        public void setValue(final T value) {
            resultObjectLock.lock();
            try {
                this.isFirst = false;
                this.value = value;
                result = null;
                rateLimiterLock.unlock();
            } finally {
                resultObjectLock.unlock();
            }
        }
        
        /** Store resulting exception and release all pending threads */
        public void setError(final Throwable throwable) {
            resultObjectLock.lock();
            try {
                this.isFirst = false;
                this.throwable = throwable;
                result = null;
                rateLimiterLock.unlock();
            } finally {
                resultObjectLock.unlock();
            }
        }
    }
    
    /** @return a result object that is shared by multiple threads. */
    public Result getResult() {
        resultObjectLock.lock();
        Result result;
        try {
            if (this.result == null) {
                this.result = new Result();
            }
            result = this.result;
        } finally {
            resultObjectLock.unlock();
        }
        rateLimiterLock.lock();
        try {
            return result;
        } finally {
            if (!result.isFirst()) {
                rateLimiterLock.unlock();
            }
        }
    }
}
