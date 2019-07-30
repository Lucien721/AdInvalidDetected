/**
 * Copyright IBM Corporation 2009-2010.
 */
package com.ibm.zrl.idmx.tests.idmx;

import junit.framework.TestCase;

import java.math.BigInteger;

import com.ibm.zrl.idmx.dm.Credential;
import com.ibm.zrl.idmx.dm.Values;
import com.ibm.zrl.idmx.issuance.Issuer;
import com.ibm.zrl.idmx.issuance.Message;
import com.ibm.zrl.idmx.key.IssuerKeyPair;
import com.ibm.zrl.idmx.issuance.update.IssuerUpdateInformation;
import com.ibm.zrl.idmx.issuance.update.UpdateSpecification;
import com.ibm.zrl.idmx.utils.Constants;
import com.ibm.zrl.idmx.utils.Parser;
import com.ibm.zrl.idmx.utils.SystemParameters;
import com.ibm.zrl.idmx.utils.Utils;
import com.ibm.zrl.idmx.utils.XMLSerializer;

/**
 * Test updatable credentials in general and attributes of type epoch in
 * particular.
 */
public class TestUpdate extends TestCase {

    /** Key pair of the issuer. */
    private IssuerKeyPair issuerKey = null;
    /** System parameters. */
    private SystemParameters sp;

    /**
     * Setup of the test environment.
     */
    protected final void setUp() {
        sp = Locations.loadParameters(TestIssuance.BASE_ID,
                TestIssuance.BASE_LOCATION);

        issuerKey = Locations.getIssuerKey();
    }

    /**
     * Test: Reads the library version and fails if the version is not the
     * expected version.
     */
    public final void testVersion() {
        if (Constants.getVersion() != "2.3.2") {
            fail("wrong version");
        }
    }

    /**
     * Test the update process.
     * 
     * @see TestIssuance#ISSUER_RECORD_CRED1C
     * @see TestIssuance#CRED1C_FN
     */
//    public final void testUpdate_Cred1c() {
//        String credStruct = TestIssuance.CRED_STRUCT_1C;
//
//        // loading elements linked to the credential structure
//        Locations.loadCredStruct(credStruct);
//        UpdateSpecification updateSpec = Locations
//                .loadUpdateSpecification(credStruct);
//
//        final IssuerUpdateInformation issuerUpdateInformation = (IssuerUpdateInformation) Parser
//                .getInstance()
//                .parse(Locations
//                        .getPrivateLocation(TestIssuance.ISSUER_RECORD_CRED1C));
//        final Credential cred = (Credential) Parser.getInstance().parse(
//                Locations.getCredentialLocation(TestIssuance.CRED1C_FN));
//
//        if (cred == null) {
//            fail("getting credential");
//        }
//        if (issuerUpdateInformation == null) {
//            fail("getting update record");
//        }
//
//        // int currentEpoch = issuerKey.getPublicKey().computeCurrentEpoch();
//        // int nextEpoch = currentEpoch + 1;
//
//        Values values = new Values(sp);
//        // Values attr1, attr2, attr3 and attr4 are updatable
//        values.add("attr3", Utils.computeRandomNumber(sp.getL_m()));
//        values.add("attr4", Utils.computeRandomNumber(sp.getL_m()));
//
//        // verify that the updates only affect attributes that are defined to be
//        // updateable
//        if (!updateSpec.verifyValues(values)) {
//            throw new RuntimeException("Updating the value of an "
//                    + "attribute: is not possible as it is not "
//                    + "defined to be updateable by the update "
//                    + "specification.");
//        }
//
//        final Message msg = Issuer.updateCredential(issuerKey, values,
//                issuerUpdateInformation);
//        XMLSerializer
//                .getInstance()
//                .serialize(
//                        issuerUpdateInformation,
//                        Locations
//                                .getPrivateLocation(TestIssuance.ISSUER_RECORD_CRED1C));
//        if (msg == null) {
//            fail("generate signature");
//        }
//        XMLSerializer.getInstance().serialize(msg,
//                issuerUpdateInformation.getUpdateLocation());
//
//        // RECIPIENT
//        // (Note that the values are sent through an orthogonal channel)
//        Message msg_recipient = (Message) Parser.getInstance().parse(
//                cred.getUpdateInformation().getUpdateLocation());
//        cred.update(msg_recipient, values);
//
//        // save the updated credential
//        XMLSerializer.getInstance().serialize(cred,
//                Locations.getCredentialLocation(TestIssuance.CRED1C_FN));
//    }
//
//    /**
//     * Test the update process.
//     * 
//     * @see TestIssuance#ISSUER_RECORD_CRED1D
//     * @see TestIssuance#CRED1D_FN
//     */
//    public final void testUpdateEpoch_Cred1d() {
//
//        String credStruct = TestIssuance.CRED_STRUCT_1D;
//
//        // loading elements linked to the credential structure
//        Locations.loadCredStruct(credStruct);
//        UpdateSpecification updateSpec = Locations
//                .loadUpdateSpecification(credStruct);
//
//        final IssuerUpdateInformation issuerUpdateInformation = (IssuerUpdateInformation) Parser
//                .getInstance()
//                .parse(Locations
//                        .getPrivateLocation(TestIssuance.ISSUER_RECORD_CRED1D));
//        final Credential cred = (Credential) Parser.getInstance().parse(
//                Locations.getCredentialLocation(TestIssuance.CRED1D_FN));
//
//        if (cred == null) {
//            fail("getting credential");
//        }
//        if (issuerUpdateInformation == null) {
//            fail("getting update record");
//        }
//
//        BigInteger currentEpoch = issuerKey.getPublicKey()
//                .computeCurrentEpoch();
//
//        Values values = new Values(sp);
//        values.add("attr4", currentEpoch);
//
//        // verify that the updates only affect attributes that are defined to be
//        // updateable
//        if (!updateSpec.verifyValues(values)) {
//            throw new RuntimeException("Updating the value of an "
//                    + "attribute: is not possible as it is not "
//                    + "defined to be updateable by the update "
//                    + "specification.");
//        }
//
//        final Message msg = Issuer.updateCredential(issuerKey, values,
//                issuerUpdateInformation);
//        XMLSerializer
//                .getInstance()
//                .serialize(
//                        issuerUpdateInformation,
//                        Locations
//                                .getPrivateLocation(TestIssuance.ISSUER_RECORD_CRED1D));
//
//        if (msg == null) {
//            fail("generate signature");
//        }
//        XMLSerializer.getInstance().serialize(msg,
//                issuerUpdateInformation.getUpdateLocation());
//
//        // RECIPIENT
//        // (Note that the values are sent through an orthogonal channel)
//        Message msg_recipient = (Message) Parser.getInstance().parse(
//                cred.getUpdateInformation().getUpdateLocation());
//        cred.update(msg_recipient, values);
//
//        // save the updated credential
//        XMLSerializer.getInstance().serialize(cred,
//                Locations.getCredentialLocation(TestIssuance.CRED1D_FN));
//    }

}
