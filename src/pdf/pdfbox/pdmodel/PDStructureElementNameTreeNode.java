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

package pdf.pdfbox.pdmodel;

import java.io.IOException;

import pdf.pdfbox.cos.COSBase;
import pdf.pdfbox.cos.COSDictionary;
import pdf.pdfbox.pdmodel.common.PDNameTreeNode;
import pdf.pdfbox.pdmodel.documentinterchange.logicalstructure.PDStructureElement;

/**
 * todo: JavaDoc
 *
 * @author John Hewson
 */
public class PDStructureElementNameTreeNode extends PDNameTreeNode<PDStructureElement>
{
    /**
     * Constructor.
     */
    public PDStructureElementNameTreeNode()
    {
        // just calls super()
    }

    /**
     * Constructor.
     *
     * @param dic The COS dictionary.
     */
    public PDStructureElementNameTreeNode( COSDictionary dic )
    {
        super(dic);
    }

    @Override
    protected PDStructureElement convertCOSToPD( COSBase base ) throws IOException
    {
        return new PDStructureElement((COSDictionary)base);
    }

    @Override
    protected PDNameTreeNode<PDStructureElement> createChildNode( COSDictionary dic )
    {
        return new PDStructureElementNameTreeNode(dic);
    }
}
