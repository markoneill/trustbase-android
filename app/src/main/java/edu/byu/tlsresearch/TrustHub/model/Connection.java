package edu.byu.tlsresearch.TrustHub.model;

/**
 * Created by sheidbri on 1/29/15.
 */
public class Connection
{
    private String clientIP;
    private int clientPort;
    private String destIP;
    private int destPort;

    public Connection(String d, int dp, String c, int cp)
    {
        destIP = d;
        destPort = dp;
        clientIP = c;
        clientPort = cp;
    }

    public String getClientIP()
    {
        return clientIP;
    }

    public int getClientPort()
    {
        return clientPort;
    }

    public String getDestIP()
    {
        return destIP;
    }

    public int getDestPort()
    {
        return destPort;
    }

    @Override
    public boolean equals(Object obj)
    {
        if (obj == null)
            return false;
        if (!(obj instanceof Connection))
            return false;
        Connection other = (Connection) obj;
        return (other.clientIP.equals(this.clientIP)
                && other.clientPort == this.clientPort
                && other.destIP.equals(this.destIP) && other.destPort == this.destPort);
    }

    @Override
    public int hashCode()
    {
        return clientIP.hashCode() ^ clientPort ^ destIP.hashCode() ^ destPort;
    }

    @Override
    public String toString()
    {
        return clientIP + ":" + clientPort + " -> " + destIP + ":" + destPort;
    }
}
