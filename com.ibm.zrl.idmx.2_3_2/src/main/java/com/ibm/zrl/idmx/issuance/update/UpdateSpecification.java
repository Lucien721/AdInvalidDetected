/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zrl.idmx.issuance.update;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Vector;

import com.ibm.zrl.idmx.dm.Values;
import com.ibm.zrl.idmx.dm.structure.AttributeStructure;

/**
 * Specification of the credential updates that will be done by the issuer. This
 * specification is referenced from the corresponding credential structure. All
 * attributes that will be updated must be known to the issuer.
 */
public class UpdateSpecification {

    /** Set of attribute names that will be updated. */
    HashSet<String> attributes;

    /**
     * Constructor.
     * 
     * @param theAttributes
     *            Attribute names of the attributes that will be updated.
     */
    public UpdateSpecification(HashSet<String> theAttributes) {
        attributes = theAttributes;
    }

    /**
     * @param values
     *            Values that should be updated.
     * @return False if an attribute of the attributes named in
     *         <code>values</code> is not in the list of updateable attributes.
     */
    public final boolean verifyValues(Values values) {
        Iterator<String> it = values.iterator();
        while (it.hasNext()) {
            String attributeName = it.next();
            if (!attributes.contains(attributeName)) {
                return false;
            }
        }
        return true;
    }

    public final Vector<AttributeStructure> getCompliantAttributeSpecVector(
            Vector<AttributeStructure> attStructs) {
        Vector<AttributeStructure> compliantAttStructs = new Vector<AttributeStructure>();
        for (AttributeStructure attStruct : attStructs){
            if (attributes.contains(attStruct.getName())) {
                compliantAttStructs.add(attStruct);
            }
        }
        return compliantAttStructs;
    }
}
