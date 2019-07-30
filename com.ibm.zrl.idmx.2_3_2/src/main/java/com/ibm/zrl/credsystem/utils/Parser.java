/**
 * Copyright IBM Corporation 2010.
 */
package com.ibm.zrl.credsystem.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.util.HashMap;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.ibm.zrl.credsystem.Translator;

/**
 * Parsing class, which loads XML files such as the translation table of the
 * Translator class.
 */
public final class Parser extends com.ibm.zrl.idmx.utils.Parser {

    /** Singleton design pattern. */
    private static Parser parser;

    /**
     * Constructor.
     */
    private Parser() {
        super();
    }

    /**
     * Singleton design pattern.
     * 
     * @return Parser object.
     */
    public static Parser getInstance() {
        if (parser == null) {
            parser = new Parser();
        }
        return parser;
    }

    /**
     * @param inputSource
     *            File name of the XML file that is to be parsed.
     * @return Element of the type as specified in the given XML file.
     * @throws IOException
     * @throws SAXException
     */
    public Object parse(final InputSource inputSource) {
        // try if it is an element already implemented
        Object result = super.parse(inputSource);

        if (result == null) {
            Element documentElement = document.getDocumentElement();

            String rootName = documentElement.getNodeName();
            if (rootName.equalsIgnoreCase("Translator")) {
                return parseTranslator(document);

            } else if (rootName.equalsIgnoreCase("CredentialNames")) {
                return parseCredentialNames(document);

            } else {
                throw (new RuntimeException("Root node (" + rootName
                        + ") of the given document: " + inputSource.toString()
                        + " is unknown."));
            }

        }
        return result;
    }

    /**
     * @param document
     *            Root of the document.
     * @return Translator.
     */
    private final Object parseTranslator(final Document document) {
        HashMap<BigInteger, Object[]> translationMap = null;

        // Parse attributes
        Element attributes = (Element) document.getElementsByTagName(
                "Attributes").item(0);
        translationMap = parseAttributeIdentifiers(attributes);

        // Create translator object
        return new Translator(translationMap);
    }

    private final HashMap<BigInteger, Object[]> parseAttributeIdentifiers(
            final Element declarations) {
        HashMap<BigInteger, Object[]> translationMap = new HashMap<BigInteger, Object[]>();

        NodeList attribute = declarations.getElementsByTagName("Attribute");
        for (int i = 0; i < attribute.getLength(); i++) {
            NamedNodeMap atts = attribute.item(i).getAttributes();
            BigInteger key = new BigInteger(getAttribute(atts, "key"));
            Object[] translatedObject = new Object[2];
            translatedObject[0] = getValue(attribute.item(i));
            translatedObject[1] = getAttribute(atts, "dataType");

            translationMap.put(key, translatedObject);
        }
        return translationMap;
    }

    private final HashMap<String, Object> parseCredentialNames(
            final Document document) {
        HashMap<String, Object> credentialNamesMap = new HashMap<String, Object>();

        NodeList attribute = document.getElementsByTagName("CredentialName");
        for (int i = 0; i < attribute.getLength(); i++) {
            String name = getAttribute(attribute.item(i).getAttributes(),
                    "name");
            Object object = getValue(attribute.item(i));

            credentialNamesMap.put(name, object);
        }

        // Create translator object
        return credentialNamesMap;
    }

}
