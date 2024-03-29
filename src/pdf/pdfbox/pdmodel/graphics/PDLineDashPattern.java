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
package pdf.pdfbox.pdmodel.graphics;

import java.util.Arrays;

import pdf.pdfbox.cos.COSArray;
import pdf.pdfbox.cos.COSBase;
import pdf.pdfbox.cos.COSInteger;
import pdf.pdfbox.pdmodel.common.COSArrayList;
import pdf.pdfbox.pdmodel.common.COSObjectable;

/**
 * A line dash pattern for stroking paths.
 * Instances of PDLineDashPattern are immutable.
 * @author Ben Litchfield
 * @author John Hewson
 */
public final class PDLineDashPattern implements COSObjectable
{
    private final int phase;
    private final float[] array;

    /**
     * Creates a new line dash pattern, with no dashes and a phase of 0.
     */
    public PDLineDashPattern()
    {
        array = new float[] { };
        phase = 0;
    }

    /**
     * Creates a new line dash pattern from a dash array and phase.
     * @param array the dash array
     * @param phase the phase
     */
    public PDLineDashPattern(COSArray array, int phase)
    {
        this.array = array.toFloatArray();
        this.phase = phase;
    }

    @Override
    public COSBase getCOSObject()
    {
        COSArray cos = new COSArray();
        cos.add(COSArrayList.converterToCOSArray(Arrays.asList(array)));
        cos.add(COSInteger.get(phase));
        return cos;
    }

    /**
     * Returns the dash phase.
     * This specifies the distance into the dash pattern at which to start the dash.
     * @return the dash phase
     */
    public int getPhase()
    {
        return phase;
    }

    /**
     * Returns the dash array.
     * @return the dash array, never null.
     */
    public float[] getDashArray()
    {
        return array.clone();
    }
}
