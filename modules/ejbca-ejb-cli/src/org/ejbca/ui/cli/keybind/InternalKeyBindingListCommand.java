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
package org.ejbca.ui.cli.keybind;

import java.io.Serializable;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.ejbca.core.ejb.keybind.InternalKeyBinding;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingProperty;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingListCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "list";
    }

    @Override
    public String getDescription() {
        return "List all available InternalKeyBindings";
    }
    
    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, CryptoTokenOfflineException, Exception {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = ejb.getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final CertificateStoreSessionRemote certificateStoreSession = ejb.getRemoteSession(CertificateStoreSessionRemote.class);
        final List<? extends InternalKeyBinding> internalKeyBindings = internalKeyBindingMgmtSession.getInternalKeyBindingInfos(getAdmin(), null);
        // Sort by type and name
        Collections.sort(internalKeyBindings, new Comparator<InternalKeyBinding>(){
            @Override
            public int compare(InternalKeyBinding o1, InternalKeyBinding o2) {
                final int typeCompare = o1.getImplementationAlias().compareTo(o1.getImplementationAlias());
                if (typeCompare != 0) {
                    return typeCompare;
                }
                return o1.getName().compareTo(o2.getName());
            }
        });
        if (internalKeyBindings.size()==0) {
            getLogger().info(" No InternalKeyBindings available or you are not authorized to view any.");
        } else {
            getLogger().info(" Type\t\"Name\" (id), Status, IssuerDN, SerialNumber, \"CryptoTokenName\" (id), KeyPairAlias, {Implementations specific properties}");
        }
        for (final InternalKeyBinding internalKeyBinding : internalKeyBindings) {
            final StringBuilder sb = new StringBuilder();
            sb.append(' ').append(internalKeyBinding.getImplementationAlias());
            sb.append('\t').append('\"').append(internalKeyBinding.getName()).append('\"');
            sb.append(" (").append(internalKeyBinding.getId()).append(')');            
            sb.append(", ").append(internalKeyBinding.getStatus().name());
            final CertificateInfo certificateInfo = certificateStoreSession.getCertificateInfo(internalKeyBinding.getCertificateId());
            String issuerDn = "n/a";
            String serialNumber = "n/a";
            if (certificateInfo != null) {
                issuerDn = certificateInfo.getIssuerDN();
                serialNumber = certificateInfo.getSerialNumber().toString(16).toUpperCase();
            }
            sb.append(", ").append(issuerDn).append(" ").append(serialNumber);
            final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
            final String cryptoTokenName = cryptoTokenManagementSession.getCryptoTokenInfo(getAdmin(), cryptoTokenId).getName();
            sb.append(", \"").append(cryptoTokenName).append("\" (").append(cryptoTokenId).append(')');
            sb.append(", ").append(internalKeyBinding.getKeyPairAlias());
            sb.append(", {");
            final List<InternalKeyBindingProperty<? extends Serializable>> properties = internalKeyBinding.getCopyOfProperties();
            for (final InternalKeyBindingProperty<? extends Serializable> property : properties) {
                sb.append("\n\t").append(property.getName()).append('=').append(property.getValue()).append(" [").append(property.getType()).append(',').append(property.getDefaultValue()).append("],");
            }
            if (properties.size() > 0) {
                sb.deleteCharAt(sb.length()-1);
            }
            sb.append("\n }");
            getLogger().info(sb);
        }
    }
}
