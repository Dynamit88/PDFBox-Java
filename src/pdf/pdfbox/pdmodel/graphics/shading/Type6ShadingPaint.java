/*
 * Copyright 2014 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package pdf.pdfbox.pdmodel.graphics.shading;

import java.awt.Color;
import java.awt.PaintContext;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.awt.image.ColorModel;
import java.io.IOException;

import pdf.pdfbox.util.Matrix;
import pdf.pdfbox.util.log.Log;
import pdf.pdfbox.util.log.LogFactory;

/**
 * AWT Paint for coons patch meshes (Type 6) shading. This was done as part of
 * GSoC2014, Tilman Hausherr is the mentor.
 *
 * @author Shaola Ren
 */
class Type6ShadingPaint extends ShadingPaint<PDShadingType6>
{
    private static final Log LOG = LogFactory.getLog(Type6ShadingPaint.class);

    /**
     * Constructor.
     *
     * @param shading the shading resources
     * @param matrix the pattern matrix concatenated with that of the parent content stream
     */
    Type6ShadingPaint(PDShadingType6 shading, Matrix matrix)
    {
        super(shading, matrix);
    }

    @Override
    public int getTransparency()
    {
        return 0;
    }

    @Override
    public PaintContext createContext(ColorModel cm, Rectangle deviceBounds, Rectangle2D userBounds,
            AffineTransform xform, RenderingHints hints)
    {
        try
        {
            return new Type6ShadingContext(shading, cm, xform, matrix, deviceBounds);
        }
        catch (IOException e)
        {
            LOG.error("An error occurred while painting", e);
            return new Color(0, 0, 0, 0).createContext(cm, deviceBounds, userBounds, xform, hints);
        }
    }
}
