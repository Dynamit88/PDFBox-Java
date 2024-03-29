/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pdf.pdfbox.pdmodel.fdf;

import java.io.IOException;
import java.io.InputStream;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class with handle some simple XML operations.
 *
 * @author Ben Litchfield
 * 
 * @deprecated Use {@link pdf.pdfbox.util.XMLUtil} instead
 */
@Deprecated
final class XMLUtil
{
    /**
     * Utility class, should not be instantiated.
     *
     */
    private XMLUtil()
    {
    }

    /**
     * This will parse an XML stream and create a DOM document.
     *
     * @param is The stream to get the XML from.
     * @return The DOM document.
     * @throws IOException It there is an error creating the dom.
     */
    public static Document parse(InputStream is) throws IOException
    {
        return pdf.pdfbox.util.XMLUtil.parse(is);
    }

    /**
     * This will get the text value of an element.
     *
     * @param node The node to get the text value for.
     * @return The text of the node.
     */
    public static String getNodeValue(Element node)
    {
        return pdf.pdfbox.util.XMLUtil.getNodeValue(node);
    }
}
