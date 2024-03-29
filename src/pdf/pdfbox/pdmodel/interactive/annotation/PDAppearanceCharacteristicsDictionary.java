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
package pdf.pdfbox.pdmodel.interactive.annotation;

import pdf.pdfbox.cos.COSArray;
import pdf.pdfbox.cos.COSBase;
import pdf.pdfbox.cos.COSDictionary;
import pdf.pdfbox.cos.COSName;
import pdf.pdfbox.cos.COSStream;
import pdf.pdfbox.pdmodel.common.COSObjectable;
import pdf.pdfbox.pdmodel.graphics.color.PDColor;
import pdf.pdfbox.pdmodel.graphics.color.PDColorSpace;
import pdf.pdfbox.pdmodel.graphics.color.PDDeviceCMYK;
import pdf.pdfbox.pdmodel.graphics.color.PDDeviceGray;
import pdf.pdfbox.pdmodel.graphics.color.PDDeviceRGB;
import pdf.pdfbox.pdmodel.graphics.form.PDFormXObject;

/**
 * This class represents an appearance characteristics dictionary.
 *
 */
public class PDAppearanceCharacteristicsDictionary implements COSObjectable
{

    private final COSDictionary dictionary;

    /**
     * Constructor.
     * 
     * @param dict dictionary
     */
    public PDAppearanceCharacteristicsDictionary(COSDictionary dict)
    {
        this.dictionary = dict;
    }

    /**
     * returns the dictionary.
     * 
     * @return the dictionary
     */
    @Override
    public COSDictionary getCOSObject()
    {
        return this.dictionary;
    }

    /**
     * This will retrieve the rotation of the annotation widget. It must be a multiple of 90. Default is 0
     * 
     * @return the rotation
     */
    public int getRotation()
    {
        return this.getCOSObject().getInt(COSName.R, 0);
    }

    /**
     * This will set the rotation.
     * 
     * @param rotation the rotation as a multiple of 90
     */
    public void setRotation(int rotation)
    {
        this.getCOSObject().setInt(COSName.R, rotation);
    }

    /**
     * This will retrieve the border color.
     * 
     * @return the border color.
     */
    public PDColor getBorderColour()
    {
        return getColor(COSName.BC);
    }

    /**
     * This will set the border color.
     * 
     * @param c the border color
     */
    public void setBorderColour(PDColor c)
    {
        this.getCOSObject().setItem(COSName.BC, c.toCOSArray());
    }

    /**
     * This will retrieve the background color.
     * 
     * @return the background color.
     */
    public PDColor getBackground()
    {
        return getColor(COSName.BG);
    }

    /**
     * This will set the background color.
     * 
     * @param c the background color
     */
    public void setBackground(PDColor c)
    {
        this.getCOSObject().setItem(COSName.BG, c.toCOSArray());
    }

    /**
     * This will retrieve the normal caption.
     * 
     * @return the normal caption.
     */
    public String getNormalCaption()
    {
        return this.getCOSObject().getString(COSName.CA);
    }

    /**
     * This will set the normal caption.
     * 
     * @param caption the normal caption
     */
    public void setNormalCaption(String caption)
    {
        this.getCOSObject().setString(COSName.CA, caption);
    }

    /**
     * This will retrieve the rollover caption.
     * 
     * @return the rollover caption.
     */
    public String getRolloverCaption()
    {
        return this.getCOSObject().getString(COSName.RC);
    }

    /**
     * This will set the rollover caption.
     * 
     * @param caption the rollover caption
     */
    public void setRolloverCaption(String caption)
    {
        this.getCOSObject().setString(COSName.RC, caption);
    }

    /**
     * This will retrieve the alternate caption.
     * 
     * @return the alternate caption.
     */
    public String getAlternateCaption()
    {
        return this.getCOSObject().getString(COSName.AC);
    }

    /**
     * This will set the alternate caption.
     * 
     * @param caption the alternate caption
     */
    public void setAlternateCaption(String caption)
    {
        this.getCOSObject().setString(COSName.AC, caption);
    }

    /**
     * This will retrieve the normal icon.
     * 
     * @return the normal icon.
     */
    public PDFormXObject getNormalIcon()
    {
        COSBase i = this.getCOSObject().getDictionaryObject(COSName.I);
        if (i instanceof COSStream)
        {
            return new PDFormXObject((COSStream)i);
        }
        return null;
    }

    /**
     * This will retrieve the rollover icon.
     * 
     * @return the rollover icon
     */
    public PDFormXObject getRolloverIcon()
    {
        COSBase i = this.getCOSObject().getDictionaryObject(COSName.RI);
        if (i instanceof COSStream)
        {
            return new PDFormXObject((COSStream)i);
        }
        return null;
    }

    /**
     * This will retrieve the alternate icon.
     * 
     * @return the alternate icon.
     */
    public PDFormXObject getAlternateIcon()
    {
        COSBase i = this.getCOSObject().getDictionaryObject(COSName.IX);
        if (i instanceof COSStream)
        {
            return new PDFormXObject((COSStream)i);
        }
        return null;
    }

    private PDColor getColor(COSName itemName)
    {
        COSBase c = this.getCOSObject().getItem(itemName);
        if (c instanceof COSArray)
        {
            PDColorSpace colorSpace;
            switch (((COSArray) c).size())
            {
            case 1:
                colorSpace = PDDeviceGray.INSTANCE;
                break;
            case 3:
                colorSpace = PDDeviceRGB.INSTANCE;
                break;
            case 4:
                colorSpace = PDDeviceCMYK.INSTANCE;
                break;
            default:
                return null;
            }
            return new PDColor((COSArray) c, colorSpace);
        }
        return null;
    }

}
