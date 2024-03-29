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
package pdf.pdfbox.contentstream.operator.markedcontent;

import pdf.pdfbox.cos.COSBase;
import pdf.pdfbox.cos.COSName;
import pdf.pdfbox.pdmodel.graphics.PDXObject;
import pdf.pdfbox.pdmodel.graphics.form.PDFormXObject;
import pdf.pdfbox.pdmodel.graphics.form.PDTransparencyGroup;
import pdf.pdfbox.text.PDFMarkedContentExtractor;

import java.io.IOException;
import java.util.List;
import pdf.pdfbox.contentstream.operator.MissingOperandException;
import pdf.pdfbox.contentstream.operator.Operator;
import pdf.pdfbox.contentstream.operator.OperatorProcessor;

/**
 * Do: Draws an XObject.
 *
 * @author Ben Litchfield
 * @author Mario Ivankovits
 */
public class DrawObject extends OperatorProcessor
{
    @Override
    public void process(Operator operator, List<COSBase> arguments) throws IOException
    {
        if (arguments.size() < 1)
        {
            throw new MissingOperandException(operator, arguments);
        }
        COSBase base0 = arguments.get(0);
        if (!(base0 instanceof COSName))
        {
            return;
        }
        COSName name = (COSName) base0;
        PDXObject xobject =  context.getResources().getXObject(name);
        ((PDFMarkedContentExtractor) context).xobject(xobject);

        if (xobject instanceof PDTransparencyGroup)
        {
            context.showTransparencyGroup((PDTransparencyGroup) xobject);
        }
        else if (xobject instanceof PDFormXObject)
        {
            PDFormXObject form = (PDFormXObject) xobject;
            context.showForm(form);
        }
    }

    @Override
    public String getName()
    {
        return "Do";
    }
}
