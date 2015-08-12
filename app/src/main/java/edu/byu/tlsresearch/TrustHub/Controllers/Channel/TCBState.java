package edu.byu.tlsresearch.TrustHub.Controllers.Channel;

import android.util.Log;

import edu.byu.tlsresearch.TrustHub.Controllers.Socket.SocketPoller;
import edu.byu.tlsresearch.TrustHub.Utils.TCPHeader;

/**
 * Created by sheidbri on 1/15/15.
 */
public enum TCBState implements ITCBState
{
    START
            {
                @Override
                public void send(TCPChannel context, byte[] transport)
                {
                    int flags = TCPHeader.getFlags(transport);
                    if (flags == TCPHeader.SYN)
                    {
                        context.setSEQ((long) Math.random());
                        context.setACK(TCPHeader.getSequenceNumber(transport) + 1);
                        context.receive(new byte[0], TCPHeader.ACK | TCPHeader.SYN);
                        context.setSEQ(context.getSEQ() + 1);

                        context.setmState(TCBState.ESTABLISHED);
                    } else
                    {
                        // Page 64 https://www.ietf.org/rfc/rfc793.txt
                        if ((flags & TCPHeader.RST) == 0)
                        {
                            int flagsToSend = TCPHeader.RST;
                            if ((flags & TCPHeader.ACK) == 0)
                            {
                                context.setSEQ(0);
                                context.setACK(TCPHeader.getSequenceNumber(transport) + TCPHeader.getPayload(transport).length);
                                flagsToSend |= TCPHeader.ACK;
                            } else
                            {
                                context.setSEQ(TCPHeader.getAckNumber(transport));
                            }
                            context.receive(new byte[0], flagsToSend);
                        }
                    }
//                        case TCPHeader.ACK:
//                            // Connection set before we started
//                            context.setmState(TCBState.ESTABLISHED);
//                            // Get the connections previous SEQ and ACK num
//                            context.setSEQ(TCPHeader.getAckNumber(transport));
//                            context.setACK(TCPHeader.getSequenceNumber(transport));
//                            context.receive(transport);
//

                }
            },
    ESTABLISHED
            {
                @Override
                public void send(TCPChannel context, byte[] transport)
                {
                    int flags = TCPHeader.getFlags(transport);
                    if ((flags & TCPHeader.RST) != 0)
                    {
                        context.close();
                    }
                    if ((flags & TCPHeader.SYN) != 0)
                    {
                        context.receive(new byte[0], TCPHeader.RST);
                        context.close();
                    }
                    if ((flags & TCPHeader.ACK) != 0)
                    {
                        Establish_ACK_handler(context, transport);
                    }
                    if ((flags & TCPHeader.FIN) != 0)
                    {
                        // Make sure to ACK the FIN (may have already been ACKed)
                        context.receive(new byte[0], TCPHeader.ACK);
                        context.receive(new byte[0], TCPHeader.FIN);
                        context.setmState(TCBState.CLOSE_WAIT);
                    }
                }
            },
    CLOSE_WAIT // We sent a FIN in response to their FIN and are waiting for ACK
            {
                @Override
                public void send(TCPChannel context, byte[] transport)
                {
                    TCBState.ESTABLISHED.send(context, transport); // TODO make sure its ack for the fin?
                    context.close();
                }
            },
    FIN_WAIT1 // SocketPoller closed and are waiting for acknowledgement
            {
                @Override
                public void send(TCPChannel context, byte[] transport)
                {
                    int flags = TCPHeader.getFlags(transport);
                    if ((flags & TCPHeader.ACK) != 0)
                    {
                        Establish_ACK_handler(context, transport);
                    }
                    if ((flags & TCPHeader.FIN) != 0)
                    {
                        context.setACK(context.getACK() + 1);
                        context.receive(new byte[0], TCPHeader.ACK);
                        context.close();
                    }
                }
            };

    @Override
    public void send(TCPChannel context, byte[] transport)
    {
        Log.d("TCPSTate", "flags: " + TCPHeader.getFlags(transport) + " state: " + context.getmState());
    }

    public void Establish_ACK_handler(TCPChannel context, byte[] transport)
    {
        if (TCPHeader.getSequenceNumber(transport) < context.getACK())
        {
            // we've already sent it (the sockets tcp that we create in socket poller
            // will guarentee it)
            return;
        }
        byte[] payload = TCPHeader.getPayload(transport);
        if (payload.length > 0) // don't send just ACK packets
        {
            context.setACK(context.getACK() + payload.length);
            // Server might not reply with anything so ACK because the java socket's
            // tcp will guarentee it's delivery

            context.receive(new byte[0], TCPHeader.ACK);
            SocketPoller.getInstance().proxySend(context.getmChannelKey(), payload);
        }
    }
}
