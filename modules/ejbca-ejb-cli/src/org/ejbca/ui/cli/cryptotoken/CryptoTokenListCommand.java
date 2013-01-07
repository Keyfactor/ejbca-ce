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
package org.ejbca.ui.cli.cryptotoken;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.SoftCryptoToken;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenListCommand extends BaseCryptoTokenCommand {

    @Override
    public String getSubCommand() {
        return "list";
    }

    @Override
    public String getDescription() {
        return "List all available CryptoTokens";
    }

    @Override
    public void executeCommand(Integer cryptoTokenId, String[] args) {
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final List<CryptoTokenInfo> cryptoTokenInfos = cryptoTokenManagementSession.getCryptoTokenInfos(getAdmin());
        // Sort by name
        Collections.sort(cryptoTokenInfos, new Comparator<CryptoTokenInfo>(){
            @Override
            public int compare(CryptoTokenInfo c1, CryptoTokenInfo c2) {
                return c1.getName().compareTo(c2.getName());
            }
        });
        getLogger().info(" \"NAME\" (ID)\t TYPE, STATUS, AUTO-ACTIVATION, TYPE-PROPERTIES...");
        for (final CryptoTokenInfo cryptoTokenInfo : cryptoTokenInfos) {
            final StringBuilder sb = new StringBuilder();
            sb.append(' ').append('\"').append(cryptoTokenInfo.getName()).append('\"');
            sb.append(" (").append(cryptoTokenInfo.getCryptoTokenId()).append(')');
            sb.append('\t').append(cryptoTokenInfo.getType());
            sb.append(", ").append(cryptoTokenInfo.isActive()?"active":"offline");
            sb.append(", ").append(cryptoTokenInfo.isAutoActivation()?"auto":"manual");
            if (SoftCryptoToken.class.getSimpleName().equals(cryptoTokenInfo.getType())) {
                sb.append(", ").append(cryptoTokenInfo.isAllowExportPrivateKey()?"exportable":"non-exportable");
            }
            if (PKCS11CryptoToken.class.getSimpleName().equals(cryptoTokenInfo.getType())) {
                sb.append(", library=").append(cryptoTokenInfo.getP11Library());
                sb.append(", slot=").append(cryptoTokenInfo.getP11Slot());
                sb.append(", attributes=").append(cryptoTokenInfo.getP11AttributeFile());
            }
            getLogger().info(sb);
        }
    }
}
