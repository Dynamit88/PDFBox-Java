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

import java.io.IOException;
import java.util.List;

import pdf.pdfbox.cos.COSBase;
import pdf.pdfbox.cos.COSDictionary;
import pdf.pdfbox.cos.COSName;
import pdf.pdfbox.contentstream.operator.Operator;
import pdf.pdfbox.contentstream.operator.OperatorProcessor;

/**
 * BDC : Begins a marked-content sequence with property list.
 *
 * @author Johannes Koch
 */
public class BeginMarkedContentSequenceWithProperties extends OperatorProcessor
{
    @Override
    public void process(Operator operator, List<COSBase> arguments) throws IOException
    {
        COSName tag = null;
        COSDictionary properties = null;
        for (COSBase argument : arguments)
        {
            if (argument instanceof COSName)
            {
                tag = (COSName) argument;
            }
            else if (argument instanceof COSDictionary)
            {
                properties = (COSDictionary) argument;
            }
        }
        this.context.beginMarkedContentSequence(tag, properties);
    }

    @Override
    public String getName()
    {
        return "BDC";
    }
}
