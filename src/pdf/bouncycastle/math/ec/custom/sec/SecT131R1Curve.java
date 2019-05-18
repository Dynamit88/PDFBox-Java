package pdf.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import pdf.bouncycastle.math.ec.ECCurve;
import pdf.bouncycastle.math.ec.ECCurve.AbstractF2m;
import pdf.bouncycastle.math.ec.ECFieldElement;
import pdf.bouncycastle.math.ec.ECLookupTable;
import pdf.bouncycastle.math.ec.ECPoint;
import pdf.bouncycastle.math.raw.Nat192;
import pdf.bouncycastle.util.encoders.Hex;

public class SecT131R1Curve extends AbstractF2m
{
    private static final int SecT131R1_DEFAULT_COORDS = COORD_LAMBDA_PROJECTIVE;

    protected SecT131R1Point infinity;

    public SecT131R1Curve()
    {
        super(131, 2, 3, 8);

        this.infinity = new SecT131R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1, Hex.decode("07A11B09A76B562144418FF3FF8C2570B8")));
        this.b = fromBigInteger(new BigInteger(1, Hex.decode("0217C05610884B63B9C6C7291678F9D341")));
        this.order = new BigInteger(1, Hex.decode("0400000000000000023123953A9464B54D"));
        this.cofactor = BigInteger.valueOf(2);

        this.coord = SecT131R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecT131R1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_LAMBDA_PROJECTIVE:
            return true;
        default:
            return false;
        }
    }

    public int getFieldSize()
    {
        return 131;
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecT131FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecT131R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecT131R1Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }

    public boolean isKoblitz()
    {
        return false;
    }

    public int getM()
    {
        return 131;
    }

    public boolean isTrinomial()
    {
        return false;
    }

    public int getK1()
    {
        return 2;
    }

    public int getK2()
    {
        return 3;
    }

    public int getK3()
    {
        return 8;
    }

    public ECLookupTable createCacheSafeLookupTable(ECPoint[] points, int off, final int len)
    {
        final int FE_LONGS = 3;

        final long[] table = new long[len * FE_LONGS * 2];
        {
            int pos = 0;
            for (int i = 0; i < len; ++i)
            {
                ECPoint p = points[off + i];
                Nat192.copy64(((SecT131FieldElement)p.getRawXCoord()).x, 0, table, pos); pos += FE_LONGS;
                Nat192.copy64(((SecT131FieldElement)p.getRawYCoord()).x, 0, table, pos); pos += FE_LONGS;
            }
        }

        return new ECLookupTable()
        {
            public int getSize()
            {
                return len;
            }

            public ECPoint lookup(int index)
            {
                long[] x = Nat192.create64(), y = Nat192.create64();
                int pos = 0;

                for (int i = 0; i < len; ++i)
                {
                    long MASK = ((i ^ index) - 1) >> 31;

                    for (int j = 0; j < FE_LONGS; ++j)
                    {
                        x[j] ^= table[pos + j] & MASK;
                        y[j] ^= table[pos + FE_LONGS + j] & MASK;
                    }

                    pos += (FE_LONGS * 2);
                }

                return createRawPoint(new SecT131FieldElement(x), new SecT131FieldElement(y), false);
            }
        };
    }
}
