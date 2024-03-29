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
package pdf.pdfbox.contentstream.operator.state;

import java.io.IOException;
import java.util.List;

import pdf.pdfbox.contentstream.operator.MissingOperandException;
import pdf.pdfbox.contentstream.operator.Operator;
import pdf.pdfbox.contentstream.operator.OperatorProcessor;
import pdf.pdfbox.cos.COSBase;
import pdf.pdfbox.cos.COSName;
import pdf.pdfbox.pdmodel.graphics.state.PDExtendedGraphicsState;
import pdf.pdfbox.util.log.Log;
import pdf.pdfbox.util.log.LogFactory;

/**
 * gs: Set parameters from graphics state parameter dictionary.
 *
 * @author Ben Litchfield
 */
public class SetGraphicsStateParameters extends OperatorProcessor
{
    private static final Log LOG = LogFactory.getLog(SetGraphicsStateParameters.class);

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
        
        // set parameters from graphics state parameter dictionary
        COSName graphicsName = (COSName) base0;
        PDExtendedGraphicsState gs = context.getResources().getExtGState(graphicsName);
        if (gs == null)
        {
            LOG.error("name for 'gs' operator not found in resources: /" + graphicsName.getName());
            return;
        }
        gs.copyIntoGraphicsState( context.getGraphicsState() );
    }

    @Override
    public String getName()
    {
        return "gs";
    }
}
