package org.jscep.message;

import static org.jscep.asn1.ScepObjectIdentifier.*;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.jscep.transaction.FailInfo;
import org.jscep.transaction.MessageType;
import org.jscep.transaction.Nonce;
import org.jscep.transaction.PkiStatus;
import org.jscep.transaction.TransactionId;

class AttributeTableFactory {
    /**
     * Creates a new {@code AttributeTable} for the given {@code PkiMessage}.
     *
     * @param message
     *            the message to parse.
     * @return the attributes from the message.
     */
    public AttributeTable fromPkiMessage(final PkiMessage<?> message) {
        Hashtable<ASN1ObjectIdentifier, Attribute> table = new Hashtable<ASN1ObjectIdentifier, Attribute>();

        List<Attribute> attributes = getMessageAttributes(message);
        if (message instanceof CertRep) {
            attributes.addAll(getResponseAttributes((CertRep) message));
        }

        for (Attribute attribute : attributes) {
            table.put(attribute.getAttrType(), attribute);
        }

        return new AttributeTable(table);
    }

    /**
     * @param message
     *            the message to parse.
     * @return the attributes in list form.
     */
    private List<Attribute> getMessageAttributes(final PkiMessage<?> message) {
        List<Attribute> attributes = new ArrayList<Attribute>();

        attributes.add(toAttribute(message.getTransactionId()));
        attributes.add(toAttribute(message.getMessageType()));
        attributes
                .add(toAttribute(message.getSenderNonce(), SENDER_NONCE.id()));

        return attributes;
    }

    /**
     * @param message
     *            the message to parse.
     * @return the attributes in list form.
     */
    private List<Attribute> getResponseAttributes(final CertRep message) {
        List<Attribute> attributes = new ArrayList<Attribute>();

        attributes.add(toAttribute(message.getPkiStatus()));
        attributes.add(toAttribute(message.getRecipientNonce(),
                RECIPIENT_NONCE.id()));
        if (message.getPkiStatus() == PkiStatus.FAILURE) {
            attributes.add(toAttribute(message.getFailInfo()));
        }

        return attributes;
    }

    /**
     * @param failInfo
     *            the failure reason to convert.
     * @return the converted attribute.
     */
    private Attribute toAttribute(final FailInfo failInfo) {
        ASN1ObjectIdentifier oid = toOid(FAIL_INFO.id());

        return new Attribute(oid, new DERSet(new DERPrintableString(
                Integer.toString(failInfo.getValue()))));
    }

    /**
     * @param pkiStatus
     *            the PKI status.
     * @return the converted attribute.
     */
    private Attribute toAttribute(final PkiStatus pkiStatus) {
        ASN1ObjectIdentifier oid = toOid(PKI_STATUS.id());

        return new Attribute(oid, new DERSet(new DERPrintableString(
                Integer.toString(pkiStatus.getValue()))));
    }

    /**
     * @param nonce
     *            the nonce to convert
     * @param id
     *            the object ID.
     * @return the converted attribute.
     */
    private Attribute toAttribute(final Nonce nonce, final String id) {
        ASN1ObjectIdentifier oid = toOid(id);

        return new Attribute(oid, new DERSet(new DEROctetString(
                nonce.getBytes())));
    }

    /**
     * @param messageType
     *            the message type.
     * @return the converted attribute.
     */
    private Attribute toAttribute(final MessageType messageType) {
        ASN1ObjectIdentifier oid = toOid(MESSAGE_TYPE.id());
        return new Attribute(oid, new DERSet(new DERPrintableString(
                Integer.toString(messageType.getValue()))));
    }

    /**
     *
     * @param transId
     *            the transaction ID
     * @return the converted attribute.
     */
    private Attribute toAttribute(final TransactionId transId) {
        ASN1ObjectIdentifier oid = toOid(TRANS_ID.id());
        return new Attribute(oid, new DERSet(new DERPrintableString(
                transId.toString())));
    }

    /**
     * @param oid
     *            the OID in {@code String} format.
     * @return the converted OID.
     */
    private ASN1ObjectIdentifier toOid(final String oid) {
        return new ASN1ObjectIdentifier(oid);
    }
}
