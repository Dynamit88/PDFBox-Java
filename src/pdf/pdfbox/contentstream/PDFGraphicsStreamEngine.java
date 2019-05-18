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
package pdf.pdfbox.contentstream;

import java.awt.geom.Point2D;
import java.io.IOException;

import pdf.pdfbox.contentstream.operator.color.SetNonStrokingColor;
import pdf.pdfbox.contentstream.operator.color.SetNonStrokingColorN;
import pdf.pdfbox.contentstream.operator.color.SetNonStrokingColorSpace;
import pdf.pdfbox.contentstream.operator.color.SetNonStrokingDeviceCMYKColor;
import pdf.pdfbox.contentstream.operator.color.SetNonStrokingDeviceGrayColor;
import pdf.pdfbox.contentstream.operator.color.SetNonStrokingDeviceRGBColor;
import pdf.pdfbox.contentstream.operator.color.SetStrokingColor;
import pdf.pdfbox.contentstream.operator.color.SetStrokingColorN;
import pdf.pdfbox.contentstream.operator.color.SetStrokingColorSpace;
import pdf.pdfbox.contentstream.operator.color.SetStrokingDeviceCMYKColor;
import pdf.pdfbox.contentstream.operator.color.SetStrokingDeviceGrayColor;
import pdf.pdfbox.contentstream.operator.color.SetStrokingDeviceRGBColor;
import pdf.pdfbox.contentstream.operator.graphics.AppendRectangleToPath;
import pdf.pdfbox.contentstream.operator.graphics.BeginInlineImage;
import pdf.pdfbox.contentstream.operator.graphics.ClipEvenOddRule;
import pdf.pdfbox.contentstream.operator.graphics.ClipNonZeroRule;
import pdf.pdfbox.contentstream.operator.graphics.CloseAndStrokePath;
import pdf.pdfbox.contentstream.operator.graphics.CloseFillEvenOddAndStrokePath;
import pdf.pdfbox.contentstream.operator.graphics.CloseFillNonZeroAndStrokePath;
import pdf.pdfbox.contentstream.operator.graphics.ClosePath;
import pdf.pdfbox.contentstream.operator.graphics.CurveTo;
import pdf.pdfbox.contentstream.operator.graphics.CurveToReplicateFinalPoint;
import pdf.pdfbox.contentstream.operator.graphics.CurveToReplicateInitialPoint;
import pdf.pdfbox.contentstream.operator.graphics.DrawObject;
import pdf.pdfbox.contentstream.operator.graphics.EndPath;
import pdf.pdfbox.contentstream.operator.graphics.FillEvenOddAndStrokePath;
import pdf.pdfbox.contentstream.operator.graphics.FillEvenOddRule;
import pdf.pdfbox.contentstream.operator.graphics.FillNonZeroAndStrokePath;
import pdf.pdfbox.contentstream.operator.graphics.FillNonZeroRule;
import pdf.pdfbox.contentstream.operator.graphics.LegacyFillNonZeroRule;
import pdf.pdfbox.contentstream.operator.graphics.LineTo;
import pdf.pdfbox.contentstream.operator.graphics.MoveTo;
import pdf.pdfbox.contentstream.operator.graphics.ShadingFill;
import pdf.pdfbox.contentstream.operator.graphics.StrokePath;
import pdf.pdfbox.contentstream.operator.markedcontent.BeginMarkedContentSequence;
import pdf.pdfbox.contentstream.operator.markedcontent.BeginMarkedContentSequenceWithProperties;
import pdf.pdfbox.contentstream.operator.markedcontent.EndMarkedContentSequence;
import pdf.pdfbox.contentstream.operator.state.Concatenate;
import pdf.pdfbox.contentstream.operator.state.Restore;
import pdf.pdfbox.contentstream.operator.state.Save;
import pdf.pdfbox.contentstream.operator.state.SetFlatness;
import pdf.pdfbox.contentstream.operator.state.SetGraphicsStateParameters;
import pdf.pdfbox.contentstream.operator.state.SetLineCapStyle;
import pdf.pdfbox.contentstream.operator.state.SetLineDashPattern;
import pdf.pdfbox.contentstream.operator.state.SetLineJoinStyle;
import pdf.pdfbox.contentstream.operator.state.SetLineMiterLimit;
import pdf.pdfbox.contentstream.operator.state.SetLineWidth;
import pdf.pdfbox.contentstream.operator.state.SetMatrix;
import pdf.pdfbox.contentstream.operator.state.SetRenderingIntent;
import pdf.pdfbox.contentstream.operator.text.BeginText;
import pdf.pdfbox.contentstream.operator.text.EndText;
import pdf.pdfbox.contentstream.operator.text.MoveText;
import pdf.pdfbox.contentstream.operator.text.MoveTextSetLeading;
import pdf.pdfbox.contentstream.operator.text.NextLine;
import pdf.pdfbox.contentstream.operator.text.SetCharSpacing;
import pdf.pdfbox.contentstream.operator.text.SetFontAndSize;
import pdf.pdfbox.contentstream.operator.text.SetTextHorizontalScaling;
import pdf.pdfbox.contentstream.operator.text.SetTextLeading;
import pdf.pdfbox.contentstream.operator.text.SetTextRenderingMode;
import pdf.pdfbox.contentstream.operator.text.SetTextRise;
import pdf.pdfbox.contentstream.operator.text.SetWordSpacing;
import pdf.pdfbox.contentstream.operator.text.ShowText;
import pdf.pdfbox.contentstream.operator.text.ShowTextAdjusted;
import pdf.pdfbox.contentstream.operator.text.ShowTextLine;
import pdf.pdfbox.contentstream.operator.text.ShowTextLineAndSpace;
import pdf.pdfbox.cos.COSName;
import pdf.pdfbox.pdmodel.PDPage;
import pdf.pdfbox.pdmodel.graphics.image.PDImage;

/**
 * PDFStreamEngine subclass for advanced processing of graphics.
 * This class should be subclassed by end users looking to hook into graphics operations.
 *
 * @author John Hewson
 */
public abstract class PDFGraphicsStreamEngine extends PDFStreamEngine
{
    // may be null, for example if the stream is a tiling pattern
    private final PDPage page;

    /**
     * Constructor.
     */
    protected PDFGraphicsStreamEngine(PDPage page)
    {
        this.page = page;

        addOperator(new CloseFillNonZeroAndStrokePath());
        addOperator(new FillNonZeroAndStrokePath());
        addOperator(new CloseFillEvenOddAndStrokePath());
        addOperator(new FillEvenOddAndStrokePath());
        addOperator(new BeginInlineImage());
        addOperator(new BeginText());
        addOperator(new CurveTo());
        addOperator(new Concatenate());
        addOperator(new SetStrokingColorSpace());
        addOperator(new SetNonStrokingColorSpace());
        addOperator(new SetLineDashPattern());
        addOperator(new DrawObject()); // special graphics version
        addOperator(new EndText());
        addOperator(new FillNonZeroRule());
        addOperator(new LegacyFillNonZeroRule());
        addOperator(new FillEvenOddRule());
        addOperator(new SetStrokingDeviceGrayColor());
        addOperator(new SetNonStrokingDeviceGrayColor());
        addOperator(new SetGraphicsStateParameters());
        addOperator(new ClosePath());
        addOperator(new SetFlatness());
        addOperator(new SetLineJoinStyle());
        addOperator(new SetLineCapStyle());
        addOperator(new SetStrokingDeviceCMYKColor());
        addOperator(new SetNonStrokingDeviceCMYKColor());
        addOperator(new LineTo());
        addOperator(new MoveTo());
        addOperator(new SetLineMiterLimit());
        addOperator(new EndPath());
        addOperator(new Save());
        addOperator(new Restore());
        addOperator(new AppendRectangleToPath());
        addOperator(new SetStrokingDeviceRGBColor());
        addOperator(new SetNonStrokingDeviceRGBColor());
        addOperator(new SetRenderingIntent());
        addOperator(new CloseAndStrokePath());
        addOperator(new StrokePath());
        addOperator(new SetStrokingColor());
        addOperator(new SetNonStrokingColor());
        addOperator(new SetStrokingColorN());
        addOperator(new SetNonStrokingColorN());
        addOperator(new ShadingFill());
        addOperator(new NextLine());
        addOperator(new SetCharSpacing());
        addOperator(new MoveText());
        addOperator(new MoveTextSetLeading());
        addOperator(new SetFontAndSize());
        addOperator(new ShowText());
        addOperator(new ShowTextAdjusted());
        addOperator(new SetTextLeading());
        addOperator(new SetMatrix());
        addOperator(new SetTextRenderingMode());
        addOperator(new SetTextRise());
        addOperator(new SetWordSpacing());
        addOperator(new SetTextHorizontalScaling());
        addOperator(new CurveToReplicateInitialPoint());
        addOperator(new SetLineWidth());
        addOperator(new ClipNonZeroRule());
        addOperator(new ClipEvenOddRule());
        addOperator(new CurveToReplicateFinalPoint());
        addOperator(new ShowTextLine());
        addOperator(new ShowTextLineAndSpace());
        addOperator(new BeginMarkedContentSequence());
        addOperator(new BeginMarkedContentSequenceWithProperties());
        addOperator(new EndMarkedContentSequence());
    }

    /**
     * Returns the page.
     * 
     * @return the page.
     * 
     */
    protected final PDPage getPage()
    {
        return page;
    }

    /**
     * Append a rectangle to the current path.
     * 
     * @param p0 point P0 of the rectangle.
     * @param p1 point P1 of the rectangle.
     * @param p2 point P2 of the rectangle.
     * @param p3 point P3 of the rectangle.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void appendRectangle(Point2D p0, Point2D p1,
                                         Point2D p2, Point2D p3) throws IOException;

    /**
     * Draw the image.
     *
     * @param pdImage The image to draw.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void drawImage(PDImage pdImage) throws IOException;

    /**
     * Modify the current clipping path by intersecting it with the current path. The clipping path will not be updated
     * until the succeeding painting operator is called.
     *
     * @param windingRule The winding rule which will be used for clipping.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void clip(int windingRule) throws IOException;

    /**
     * Starts a new path at (x,y).
     * 
     * @param x x-coordinate of the target point.
     * @param y y-coordinate of the target point.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void moveTo(float x, float y) throws IOException;

    /**
     * Draws a line from the current point to (x,y).
     * 
     * @param x x-coordinate of the end point of the line.
     * @param y y-coordinate of the end point of the line.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void lineTo(float x, float y) throws IOException;

    /**
     * Draws a curve from the current point to (x3,y3) using (x1,y1) and (x2,y2) as control points.
     * 
     * @param x1 x-coordinate of the first control point.
     * @param y1 y-coordinate of the first control point.
     * @param x2 x-coordinate of the second control point.
     * @param y2 y-coordinate of the second control point.
     * @param x3 x-coordinate of the end point of the curve.
     * @param y3 y-coordinate of the end point of the curve.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void curveTo(float x1, float y1,
                                 float x2, float y2,
                                 float x3, float y3) throws IOException;

    /**
     * Returns the current point of the current path.
     * 
     * @return the current point.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract Point2D getCurrentPoint() throws IOException;

    /**
     * Closes the current path.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void closePath() throws IOException;

    /**
     * Ends the current path without filling or stroking it. The clipping path is updated here.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void endPath() throws IOException;

    /**
     * Stroke the path.
     *
     * @throws IOException If there is an IO error while stroking the path.
     */
    public abstract void strokePath() throws IOException;

    /**
     * Fill the path.
     *
     * @param windingRule The winding rule this path will use.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void fillPath(int windingRule) throws IOException;

    /**
     * Fills and then strokes the path.
     *
     * @param windingRule The winding rule this path will use.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void fillAndStrokePath(int windingRule) throws IOException;

    /**
     * Fill with Shading.
     *
     * @param shadingName The name of the Shading Dictionary to use for this fill instruction.
     * 
     * @throws IOException if something went wrong.
     */
    public abstract void shadingFill(COSName shadingName) throws IOException;
}
