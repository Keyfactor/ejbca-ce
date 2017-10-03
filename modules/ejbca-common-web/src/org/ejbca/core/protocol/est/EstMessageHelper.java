package org.ejbca.core.protocol.est;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalEjbcaResources;
import java.security.SecureRandom;

public class EstMessageHelper {
    private static Logger LOG = Logger.getLogger(EstMessageHelper.class);
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();
    private static final SecureRandom secureRandom = new SecureRandom();

    private static final String EST_ERRORGENERAL = "est.errorgeneral";

}