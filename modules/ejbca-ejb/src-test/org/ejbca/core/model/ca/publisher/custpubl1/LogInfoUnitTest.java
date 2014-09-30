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
package org.ejbca.core.model.ca.publisher.custpubl1;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.Date;

import org.apache.log4j.Logger;
import org.junit.Test;

/**
 * Test case for LogInfo class handling encoding of the log entries.
 *
 * @version $Id$
 */
public class LogInfoUnitTest {

    private static final Logger log = Logger.getLogger(LogInfoUnitTest.class);

    @Test
    public void testConstructAndEncode() throws Exception {
        
        Date expectedDate = new Date(4711);
        String expectedLevel = "info";
        String expectedMessage = "Some message";

        // Test first constructor
        CustomerLdapPublisher1.LogInfo instance = new CustomerLdapPublisher1.LogInfo(expectedDate, expectedLevel, expectedMessage);
        assertEquals("get date", expectedDate, instance.getTime());
        assertEquals("get level", expectedLevel, instance.getLevel());
        assertEquals("get msg", expectedMessage, instance.getMsg());
        
        assertEquals("default sqn", null, instance.getSqn());
        assertEquals("default stage", null, instance.getStage());
        assertEquals("default msgid", null, instance.getMsgid());
        assertEquals("default pid", null, instance.getPid());
        assertEquals("default msgext", null, instance.getMsgext());
        
        assertEquals("get encoded 1", " time:19700101000004.711Z sqn: stage: level:info msgid: msg:Some message pid: msgext:", instance.getEncoded());
        
        // Test second constructor
        Integer expectedSqn = 13;
        String expectedStage = "Download";
        String expectedMsgid = "023";
        String expectedPid = "123123";
        String expectedMsgext = "uploadtype=DSC lastTryTime=20121030121233Z lastTryTime=20121030121233.12Z";
        
        instance = new CustomerLdapPublisher1.LogInfo(expectedDate, expectedSqn, expectedStage, expectedLevel, expectedMsgid, expectedMessage, expectedPid, expectedMsgext);
        assertEquals("get date", expectedDate, instance.getTime());
        assertEquals("get sqn", expectedSqn, instance.getSqn());
        assertEquals("get stage", expectedStage, instance.getStage());
        assertEquals("get level", expectedLevel, instance.getLevel());
        assertEquals("get msgid", expectedMsgid, instance.getMsgid());
        assertEquals("get msg", expectedMessage, instance.getMsg());
        assertEquals("get pid", expectedPid, instance.getPid());
        assertEquals("get msgext", expectedMsgext, instance.getMsgext());
        
        log.debug(instance.getEncoded());
        assertEquals("get encoded 2", " time:19700101000004.711Z sqn:13 stage:Download level:info msgid:023 msg:Some message pid:123123 msgext:uploadtype=DSC lastTryTime=20121030121233Z lastTryTime=20121030121233.12Z", instance.getEncoded());
        
        // Test erroneus msgid
        try {
            String erronousMsgid = "1234";
            CustomerLdapPublisher1.LogInfo logInfo = new CustomerLdapPublisher1.LogInfo(expectedDate, expectedSqn, expectedStage, expectedLevel, erronousMsgid, expectedMessage, null, expectedMsgext);
            logInfo.getClass(); // Just to not warn about unused variable
            fail("Should have thrown exception as msgid must be 3 characters if provided");
        } catch (IllegalArgumentException ok) {} // NOPMD
        
        assertNotNull("toString", instance.toString());
    }

    
    
    
}
