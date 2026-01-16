/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.proxyca;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class KeyFactorCommandSessionBeanUnitTest {

    private KeyFactorCommandSessionBean keyFactorCommandSessionBean;

    @Before
    public void setUp() {
        keyFactorCommandSessionBean = new KeyFactorCommandSessionBean();
    }

    @Test
    public void testGetUrl() {
        assertEquals("a/b/c/d", keyFactorCommandSessionBean.getUrl("a/b", "c/d"));
        assertEquals("a/b/c/d", keyFactorCommandSessionBean.getUrl("a/b/", "c/d"));
        assertEquals("a/b/c/d", keyFactorCommandSessionBean.getUrl("a/b", "/c/d"));
        assertEquals("a/b/c/d", keyFactorCommandSessionBean.getUrl("a/b/", "/c/d"));
    }

}
