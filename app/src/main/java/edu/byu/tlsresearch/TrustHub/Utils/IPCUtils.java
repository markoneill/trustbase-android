package edu.byu.tlsresearch.TrustHub.Utils;

import android.os.Bundle;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.Serializable;

import edu.byu.tlsresearch.TrustHub.API.PluginInterface;

/**
 * Created by ben on 8/11/15.
 * Contains methods for facilitating interprocess communication (IPC) for Android.
 */
public class IPCUtils {

    private static final String TAG= "IPCUtils";

    /*
        Turns any Serializable object into a Bundle which can be passed via IPC.
        EDIT: Allowed bundle to process any object.  Hopefully this will work with X509Certificates.
     */
    public static Bundle bundle(Object obj)
    {
        ByteArrayOutputStream holder = new ByteArrayOutputStream();
        ObjectOutput out = null;
        byte[] bytes = null;
        try {
            out = new ObjectOutputStream(holder);
            out.writeObject(obj);
            bytes = holder.toByteArray();
        }
        catch (IOException e) {
            Log.e(TAG + " bundle", "Error loading output stream.");
            return null;
        }
        finally {
            //Close streams
            try {
                if (out != null) {
                    out.close();
                }
            } catch (IOException ex) {
                // ignore close exception
            }
            try {
                holder.close();
            } catch (IOException ex) {
                // ignore close exception
            }
        }

        if(bytes != null) {
            Bundle b = new Bundle();
            b.putByteArray("data", bytes);
            return b;
        }
        else
            return null;
    }

    /*
        Retrieves serialized objects packed using bundle(Serializable obj).
     */
    public static Object unbundle(Bundle b)
    {
        byte[] bytes = b.getByteArray("data");
        Object obj = null;
        ByteArrayInputStream holder = new ByteArrayInputStream(bytes);
        ObjectInput in = null;

        try {
            in = new ObjectInputStream(holder);
            obj = in.readObject();
        }
        catch(IOException e)
        {
            Log.e(TAG + " unbundle", "Error reading from bundle");
            return null;
        }
        catch(ClassNotFoundException e)
        {
            Log.e(TAG + " unbundle", "Class not found\n" + e.getMessage());
            return null;
        }
        finally
        {
            //Close streams.
            try {if(in != null) in.close();}
            catch(IOException e) {/*Do nothing*/}

            try {holder.close();}
            catch(IOException e) {/*Do nothing*/}
        }

        return obj;
    }

    /*
        Converts from POLICY_RESPONSE to int for IPC.
     */
    public static int PolicyResponseToInt(PluginInterface.POLICY_RESPONSE resp)
    {
        switch(resp)
        {
            case VALID:
                return 0;
            case INVALID:
                return 1;
            case VALID_PROXY:
                return 2;
            default:
                //Invalid code. Return INVALID.
                Log.e(TAG + " PR2Int", "Invalid POLICY_RESPONSE");
                return 1;
        }
    }

    /*
        Converts from int to POLICY_RESPONSE for IPC.
     */
    public static PluginInterface.POLICY_RESPONSE IntToPolicyResponse(int code)
    {
        switch(code)
        {
            case 0:
                return PluginInterface.POLICY_RESPONSE.VALID;
            case 1:
                return PluginInterface.POLICY_RESPONSE.INVALID;
            case 2:
                return PluginInterface.POLICY_RESPONSE.VALID_PROXY;
            default:
                //Invalid code.  Return INVALID.
                Log.e(TAG + " Int2PR", "Invalid int code");
                return PluginInterface.POLICY_RESPONSE.INVALID;
        }
    }

}
