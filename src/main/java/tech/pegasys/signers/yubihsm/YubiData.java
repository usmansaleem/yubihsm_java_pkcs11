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
 * Extends Data to provide support for ID (for findObjectInit)
 */
public class YubiData extends Data {

    /**
     * The ID (CKA_ID) attribute of this data object (DER-encoded).
     */
    protected ByteArrayAttribute id;

    public YubiData() {
        super();
    }

    @Override
    protected void allocateAttributes() {
        super.allocateAttributes();
        id = new ByteArrayAttribute(Attribute.ID);
        attributeTable.put(Attribute.ID, id);
    }

    public ByteArrayAttribute getId() {
        return id;
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
