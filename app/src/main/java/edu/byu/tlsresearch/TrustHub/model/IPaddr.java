package edu.byu.tlsresearch.TrustHub.model;

public class IPaddr
{

    private short firstOct;
    private short secondOct;
    private short thirdOct;
    private short fourthOct;
    private short mask;

    public IPaddr(short first, short second, short third, short fourth)
    {
        firstOct = first;
        secondOct = second;
        thirdOct = third;
        fourthOct = fourth;
        mask = 0;
    }
    public IPaddr()
    {

    }

    @Override
    public String toString()
    {
        return firstOct + "." + secondOct + "." + thirdOct + "." + fourthOct;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null)
            return false;
        if (this == obj)
            return true;
        if (!(obj instanceof IPaddr))
            return false;
        IPaddr other = (IPaddr) obj;
        return this.toString().equals(other.toString());
    }

    @Override
    public int hashCode()
    {
        return firstOct ^ secondOct ^ thirdOct ^ fourthOct;
    }

    public void setAddress(String toParse)
    {
        String[] octs = toParse.split("\\.");
        if(octs.length == 4)
        {
            firstOct = Short.parseShort(octs[0]);
            secondOct = Short.parseShort(octs[1]);
            thirdOct = Short.parseShort(octs[2]);
            fourthOct = Short.parseShort(octs[3]);
        }
    }

    public short getFirstOct()
    {
        return firstOct;
    }

    public short getSecondOct()
    {
        return secondOct;
    }

    public short getThirdOct()
    {
        return thirdOct;
    }

    public short getFourthOct()
    {
        return fourthOct;
    }

    public short getMask()
    {
        return mask;
    }

    public void setMask(short mask)
    {
        this.mask = mask;
    }
}
