package tech.pegasys.signers.yubihsm;

import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.Util;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.Data;
import iaik.pkcs.pkcs11.objects.PKCS11Object;

import java.util.Objects;

/**
 * Extends Data to provide support for ID in place of ObjectId for findInit
 */
public class YubiData extends Data {

    /**
     * The ID (CKA_ID) attribute of this data object (DER-encoded).
     */
    // CHECKSTYLE:SKIP
    protected ByteArrayAttribute id;

    public YubiData() {
        super();
    }

    protected YubiData(Session session, long objectHandle) throws TokenException {
        super(session, objectHandle);
    }

    protected static void putAttributesInTable(YubiData object) {
        Util.requireNonNull("object", object);
        object.attributeTable.put(Attribute.ID, object.id);
    }

    @Override
    protected void allocateAttributes() {
        super.allocateAttributes();
        id = new ByteArrayAttribute(Attribute.ID);
        putAttributesInTable(this);
    }

    public static PKCS11Object getInstance(Session session, long objectHandle)
            throws TokenException {
        return new YubiData(session, objectHandle);
    }

    @Override
    public ByteArrayAttribute getObjectID() {
        return id;
    }

    @Override
    public void readAttributes(Session session) throws TokenException {
        super.readAttributes(session);
        PKCS11Object.getAttributeValue(session, objectHandle, id);
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        final YubiData yubiData = (YubiData) o;
        return id.equals(yubiData.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), id);
    }

    @Override
    public String toString() {
        String superToString = super.toString();
        return Util.concatObjectsCap(superToString.length() + 100, superToString,
                "\n  PKCS11 ID (DER, hex): ", id);
    }
}
