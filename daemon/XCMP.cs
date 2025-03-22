using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Net;
using FFmpeg.AutoGen;
using System.Collections.Concurrent;
using System.Threading.Tasks.Dataflow;
using Serilog;
using Serilog.Debugging;
using Org.BouncyCastle.Utilities;
using WebSocketSharp;
using Org.BouncyCastle.Crypto.Digests;
using netcore_cli;
using System.ComponentModel.DataAnnotations;
using System.Data.SqlTypes;
using System.Reflection.Emit;
using Org.BouncyCastle.Math.EC.Rfc7748;
using NAudio.Utils;

namespace moto_xcmp
{
    public enum XnlOpcode {
        MasterPresentBroadcast = 0x0001,
        MasterStatusBroadcast = 0x0002,
        DeviceMasterQuery = 0x0003,
        DeviceAuthKeyRequest = 0x0004,
        DeviceAuthKeyReply = 0x0005,
        DeviceConnectRequest = 0x0006,
        DeviceConnectReply = 0x0007,
        DeviceSysMapRequest = 0x0008,
        DeviceSysMapBroadcast = 0x0009,
        DeviceResetMessage = 0x000a,
        DataMessage = 0x000b,
        DataMessageAck = 0x000c
    }

    public enum XnlProtocol {
        Xnl = 0x00,
        Xcmp = 0x01
    }

    public enum XcmpType {
        Request = 0x0000,
        Reply = 0x8000,
        Broadcast = 0xb000
    }

    public enum XcmpOpcode {
        RadioStatus = 0x00e,
        RadioVersion = 0x00f,
        DeviceInitSts = 0x400,
        DisplayText = 0x401,
        IndicatorUpdate = 0x402,
        PhysUserInput = 0x405,
        TxPowerLevel = 0x408,
        MonitorControl = 0x40c,
        ChZnSel = 0x40d,
        MicControl = 0x40e,
        ScanControl = 0x40f,
        EmergencyControl = 0x413,
        AudioRoutingControl = 0x414,
        TransmitControl = 0x415,
        CallControl = 0x41e,
        EncryptionControl = 0x429
    }

    public enum DeviceType {
        Unknown = 0x00,
        RFTransceiver = 0x01,
        ControlHead = 0x02,
        Siren = 0x03,
        VehicularRepeater = 0x04,
        Consolette = 0x05,
        VehicularAdapter = 0x06,
        OptionBoard = 0x07,
        Autotest = 0x08,
        ExternalMic = 0x09,
        PCApplication = 0x0a,
        ExternalAccessory = 0x0b
    }

    public enum XcmpResult {
        Success = 0x00,
        Failure = 0x01,
        IncorrectMode = 0x02,
        OpcodeNotSupported = 0x03,
        InvalidParameter = 0x04
    }

    public interface TransportConnection : IDisposable
    {
        public void Connect();

        public void Disconnect();
        public void Send(byte[] data);

        public byte[] Receive();
    }

    // public class TCPConnection : TransportConnection {
    //     public void Connect();

    //     public void Disconnect();
    //     public void Send(byte[] data);

    //     public byte[] Receive();
    // }

    public class UDPConnection : TransportConnection {
        private UdpClient Client;
        private string Hostname;
        private int Port;
        private IPEndPoint RemoteEndPoint;
        public UDPConnection(string hostname, int port) {
            Hostname = hostname;
            Port = port;
            Client = new UdpClient(port);
            RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
        }
        public void Dispose() {
            Disconnect();
        }
        public void Connect() {
            Client.Connect(Hostname, Port);
        }

        public void Disconnect() {
            Client?.Close();
        }
        public void Send(byte[] data) {
            Client.Send(data, data.Length);
        }

        public byte[] Receive() {
            return Client.Receive(ref RemoteEndPoint);
        }
    }

    public class XNL {
        private TransportConnection RadioTransport;
        private byte TransactionIdBase;
        private byte TransactionId;
        private byte Flag;
        private int MyAddr;
        private int RadioAddr;
        private uint[] AuthKey;
        private uint AuthDelta;
        private byte AuthLevel;
        private CancellationTokenSource ts;
        private CancellationToken ct;
        /// <summary>
        /// Reference back to Radio state object for status updates
        /// </summary>
        private MotoXcmpRadio Radio;

        private Queue<byte[]> XnlQueue;

        public XNL(string addr, int port, bool udp, MotoXcmpRadio radio, uint[] authKey, uint authDelta, byte authLevel) {
            if (udp) {
                RadioTransport = new UDPConnection(addr, port);
            } else {
                throw new NotImplementedException("TCP is not implemented.");
            }
            Radio = radio;
            AuthKey = new uint[4];
            Array.Copy(authKey, 0, AuthKey, 0, 4);
            AuthDelta = authDelta;
            AuthLevel = authLevel;
            XnlQueue = new Queue<byte[]>();
        }

        public void Start() {
            Log.Debug("Starting up XCMP listener");
            RadioTransport.Connect();
            ts = new CancellationTokenSource();
            ct = ts.Token;
            Task.Factory.StartNew(receiveLoop, ct);
            Connect();
        }

        public void Stop() {
            Log.Debug("Stopping XCMP listener");
            if (ts != null)
            {
                Log.Verbose("Cancelling service token");
                ts.Cancel();
                ts.Dispose();
                ts = null;
            }
            RadioTransport.Disconnect();
        }

        private byte[] GenerateKey(byte[] challenge)
        {
            UInt32 dword1 = ArrayToInt(challenge, 0);
            UInt32 dword2 = ArrayToInt(challenge, 4);

            UInt32 sum = 0;
            UInt32 _authDelta = (uint)AuthDelta;
            UInt32 num1 = (uint)AuthKey[0];
            UInt32 num2 = (uint)AuthKey[1];
            UInt32 num3 = (uint)AuthKey[2];
            UInt32 num4 = (uint)AuthKey[3];

            for (int index = 0; index < 32; ++index)
            {
                sum += _authDelta;
                dword1 += (uint)(((int)dword2 << 4) + (int)num1 ^ (int)dword2 + (int)sum ^ (int)(dword2 >> 5) + (int)num2);
                dword2 += (uint)(((int)dword1 << 4) + (int)num3 ^ (int)dword1 + (int)sum ^ (int)(dword1 >> 5) + (int)num4);
            }
            byte[] res = new byte[8];
            IntToArray(dword1, res, 0);
            IntToArray(dword2, res, 4);
            return res;
        }

        private UInt32 ArrayToInt(byte[] data, int start)
        {
            UInt32 ret = 0;
            for (int i = 0; i < 4; i++)
            {
                ret = ret << 8 | data[i + start];
            }
            return ret;
        }

        private static void IntToArray(UInt32 i, byte[] data, int start)
        {
            for (int index = 0; index < 4; ++index)
            {
                data[start + 3 - index] = (byte)(i & (uint)byte.MaxValue);
                i >>= 8;
            }
        }

        private void Connect() {
            // send master query
            // force flag to 0
            Flag = 0;
            TransactionIdBase = 0;
            byte[] queryRet = SendXNL(XnlOpcode.DeviceMasterQuery, new byte[0]);

            // send auth key request
            byte[] keyReqRet = SendXNL(XnlOpcode.DeviceAuthKeyRequest, new byte[0]);
            byte[] authChallenge = new byte[8];
            Log.Debug("Return was {0} bytes long", keyReqRet.Length);
            Array.Copy(keyReqRet, 14, authChallenge, 0, 8);
            
            // generate key
            byte[] authResult = GenerateKey(authChallenge);
            // send conn req
            byte[] connReqData = new byte[12];
            
            // requested address
            connReqData[0] = 0x00;
            connReqData[1] = 0x00;

            // device type
            connReqData[2] = (byte) DeviceType.ControlHead;

            // auth level
            connReqData[3] = AuthLevel;

            // auth key
            Array.Copy(authResult, 0, connReqData, 4, 8);

            byte[] connReqRet = SendXNL(XnlOpcode.DeviceConnectRequest, connReqData);
            int status = connReqRet[12];
            
            if (status == 0) {
                throw new NotSupportedException("Radio authentication failed.");
            }
            TransactionIdBase = connReqRet[13];
            
            // handle sysmap bcast
            Thread.Sleep(100);
            XnlQueue.Dequeue();
            // XCMP layer to handle devinitsts
        }

        private byte[] SendXNL(XnlOpcode opcode, byte[] data, bool xcmp=false, byte? transIdIn=null, byte? flagIn=null) {
            int payloadLen = data.Length;
            byte[] toSend = new byte[payloadLen + 12];

            // frame length high and low bytes
            //int frameLen = payloadLen + 12;
            //toSend[0] = (byte)((frameLen >> 8) & 0xFF);
            //toSend[1] = (byte)(frameLen & 0xFF);

            // opcode
            toSend[0] = (byte)(((byte) opcode >> 8) & 0xFF);
            toSend[1] = (byte)((byte) opcode & 0xFF);

            // protocol
            toSend[2] = (xcmp ? (byte) 1 : (byte) 0);

            // flag
            toSend[3] = (byte) ((flagIn == null) ? Flag : flagIn);

            // destination
            toSend[4] = (byte)((RadioAddr >> 8) & 0xFF);
            toSend[5] = (byte)(RadioAddr & 0xFF);

            // source
            toSend[6] = (byte)((MyAddr >> 8) & 0xFF);
            toSend[7] = (byte)(MyAddr & 0xFF);

            // transaction ID
            toSend[8] = (byte) TransactionId;
            toSend[9] = (byte) ((transIdIn == null) ? TransactionId : transIdIn);

            // payload length high and low bytes
            toSend[10] = (byte)((payloadLen >> 8) & 0xFF);
            toSend[11] = (byte)(payloadLen & 0xFF);
            if (payloadLen > 0) {
                Array.Copy(data, 0, toSend, 12, payloadLen);
            }

            // increment our message counters
            Flag++;
            if (Flag > 7) {
                Flag = 0;
            }

            TransactionId++;
            // transaction ID should overflow by itself

            Log.Verbose("Raw bytes out: " + Convert.ToHexString(toSend));
            RadioTransport.Send(toSend);

            // return immediately if it's a data broadcast message
            if (xcmp && opcode == XnlOpcode.DataMessage) {
                int inXcmpOpcode = 0;
                inXcmpOpcode |= (data[0] << 8);
                inXcmpOpcode |= (data[1] & 0xFF);
                if (inXcmpOpcode >> 12 == 0xB) {
                    Log.Verbose("Broadcast packet received, won't try to receive one");
                    return new byte[0];
                }
                
            }

            // return immediately if it's a data ack
            if (xcmp && opcode == XnlOpcode.DataMessageAck) {
                return new byte[0];
            }
            
            // start a timer so we don't hold infinitely
            var startTime = DateTime.UtcNow;
            while (DateTime.UtcNow - startTime < TimeSpan.FromSeconds(2))
            {
                if (XnlQueue.Count > 0) {
                    int len = 0;
                    byte[] fromRadio = XnlQueue.Dequeue();
                    Log.Verbose("Dequeued: " + Convert.ToHexString(fromRadio));

                    int inOpcode = 0;
                    // check if it's an ack, if so, drop it
                    inOpcode |= (fromRadio[0] << 8);
                    inOpcode |= (fromRadio[1] & 0xFF);

                    if (inOpcode != (int) XnlOpcode.DataMessageAck) {
                        return fromRadio;
                    }
                }
            }
            throw new TimeoutException("Radio did not reply in a timely manner.");
        }

        private void receiveLoop(object _token) {
            var token = (CancellationToken)_token;
            while (!token.IsCancellationRequested) {
                try {
                    byte[] receiveBytes = RadioTransport.Receive();
                    Log.Verbose("Raw bytes in: " + Convert.ToHexString(receiveBytes));

                    int opcodeIn = 0;
                    opcodeIn |= (receiveBytes[0] << 8);
                    opcodeIn |= (receiveBytes[1] & 0xFF);

                    switch (opcodeIn) {
                        // set radio address from 
                        case (int) XnlOpcode.MasterStatusBroadcast:
                            RadioAddr = 0;
                            RadioAddr |= (receiveBytes[6] << 8);
                            RadioAddr |= (receiveBytes[7] & 0xFF);
                            Log.Debug("Setting radio address to {0} from master broadcast", RadioAddr);
                            break;
                        // set temp address during auth key request
                        case (int) XnlOpcode.DeviceAuthKeyReply:
                            MyAddr = 0;
                            MyAddr |= (receiveBytes[12] << 8);
                            MyAddr |= (receiveBytes[13] & 0xFF);
                            Log.Debug("Setting own address to {0} from auth key reply", MyAddr);
                            break;
                        // set permanent address during connection reply
                        case (int) XnlOpcode.DeviceConnectReply:
                            MyAddr = 0;
                            MyAddr |= (receiveBytes[14] << 8);
                            MyAddr |= (receiveBytes[15] & 0xFF);
                            Log.Debug("Setting own address to {0} from connection reply", MyAddr);
                            break;
                        // ACK any data messages
                        case (int) XnlOpcode.DataMessage:
                            Log.Verbose("ACKing transaction {0}", receiveBytes[9]);
                            SendXNL(XnlOpcode.DataMessageAck, new byte[0], true, receiveBytes[9], receiveBytes[3]);
                            //continue;
                            break;
                    }
                    XnlQueue.Enqueue(receiveBytes);
                }
                catch (Exception ex)
                {
                    Log.Error(ex, "Got exception in XCMP thread");
                    Stop();
                    Radio.Stop();
                }
            }
        }

        public byte[] SendData(byte[] data) {
            byte[] recv = SendXNL(XnlOpcode.DataMessage, data, true);
            if (recv.Length == 0) {
                return new byte[0];
            }
            int inLen = 0;
            inLen |= (recv[10] << 8);
            inLen |= (recv[11] & 0xFF);
            byte[] returnData = new byte[inLen];
            Array.Copy(recv, 12, returnData, 0, inLen);
            return returnData;
        }
    }

    public class XCMP {
        private XNL Xnl;

        public XCMP(string hostname, int port, bool udp, MotoXcmpRadio radio, uint[] authKey, uint authDelta, byte authLevel) {
            Xnl = new XNL(hostname, port, udp, radio, authKey, authDelta, authLevel);
        }
        public void Start() {
            Xnl.Start();
            SendDevInitSts();
        }

        public void Stop() {
            Xnl.Stop();
        }
        public byte[] Send(XcmpOpcode opcode, XcmpType type, byte[] data)
        {
            // int opcodeOut = 0;
            // opcodeOut |= (data[0] << 8);
            // opcodeOut |= (data[1] & 0xFF);

            // expects to get an XCMP opcode and some data in, length is auto calculated
            byte[] toSend = new byte[data.Length + 2];

            int fullOpcode = (int)opcode;
            fullOpcode |= (int) type;

            // opcode
            toSend[0] = (byte)(((int) fullOpcode >> 8) & 0xFF);
            toSend[1] = (byte)(fullOpcode & 0xFF);

            Array.Copy(data, 0, toSend, 2, data.Length);

            Log.Debug("Sending XCMP: " + Convert.ToHexString(toSend));

            byte[] result = Xnl.SendData(toSend);
            if (result.Length == 0) {
                return new byte[0];
            }
            int inLen = result.Length-2;
            byte[] toReturn = new byte[inLen];
            Array.Copy(result, 2, toReturn, 0, inLen);
            return toReturn;
        }

        public void SendDevInitSts() {
            byte[] stsmsg = new byte[15];
            // XCMP ver
            stsmsg[0] = 0x00;
            stsmsg[1] = 0x00;
            stsmsg[2] = 0x00;
            stsmsg[3] = 0x01;

            // init type
            stsmsg[4] = 0x00;

            // device type
            stsmsg[5] = (byte) DeviceType.ControlHead;

            // device status
            stsmsg[6] = 0x00;
            stsmsg[7] = 0x00;

            // descriptor size
            stsmsg[8] = 0x06;

            // display type generic
            stsmsg[9] = 0x02;
            stsmsg[10] = 0x0B;

            // keypad type full
            stsmsg[11] = 0x09;
            stsmsg[12] = 0x02;

            // mic type ignore hub
            stsmsg[13] = 0x03;
            stsmsg[14] = 0x02;

            Send(XcmpOpcode.DeviceInitSts, XcmpType.Broadcast, stsmsg);
        }

        /// <summary>
        /// Change channel up or down on radio
        /// </summary>
        /// <param name="down">whether or not to go down</param>
        /// <returns></returns>
        public bool ChangeChannel(bool down)
        {
            Log.Debug("Changing channel");
            byte[] chznsel = new byte[5];

            chznsel[0] = (byte) (down ? 0x04 : 0x03);
            chznsel[1] = 0x00;
            chznsel[2] = 0x00;
            chznsel[3] = 0x00;
            chznsel[4] = 0x01;

            Send(XcmpOpcode.ChZnSel, XcmpType.Request, chznsel);
            return true;
        }

        public bool ChangeZone(bool down)
        {
            Log.Debug("Changing zone");
            byte[] chznsel = new byte[5];

            chznsel[0] = (byte) (down ? 0x02 : 0x01);
            chznsel[1] = 0x00;
            chznsel[2] = 0x01;
            chznsel[3] = 0x00;
            chznsel[4] = 0x00;

            Send(XcmpOpcode.ChZnSel, XcmpType.Request, chznsel);
            return true;
        }

        public bool SetZoneChannel(int zone, int channel) {
            Log.Debug("Setting zone/channel");
            byte[] chznsel = new byte[5];

            chznsel[0] = 0x05;
            chznsel[1] = (byte)(((byte) zone >> 8) & 0xFF);
            chznsel[2] = (byte)((byte) zone & 0xFF);
            chznsel[3] = (byte)(((byte) channel >> 8) & 0xFF);
            chznsel[4] = (byte)((byte) channel & 0xFF);

            Send(XcmpOpcode.ChZnSel, XcmpType.Request, chznsel);
            return true;
        }

        public bool SetTransmit(bool tx) {
            Log.Debug("Changing transmit state");
            byte[] audiocontrol = new byte[3];

            audiocontrol[0] = 0x00;
            audiocontrol[1] = 0x00;
            audiocontrol[2] = 0x00;

            Send(XcmpOpcode.AudioRoutingControl, XcmpType.Request, audiocontrol);

            Thread.Sleep(500);
            
            byte[] txcontrol = new byte[2];

            txcontrol[0] = (byte) (tx ? 0x01 : 0x02);
            txcontrol[1] = 0x00;

            Send(XcmpOpcode.TransmitControl, XcmpType.Request, txcontrol);
            
            
            // byte[] txcontrol = new byte[5];

            // // function
            // txcontrol[0] = 0x00;
            // // source
            // txcontrol[1] = 0x02;
            // //type
            // txcontrol[2] = (byte) (tx ? 0x01 : 0x00);
            // //id
            // txcontrol[3] = 0x00;
            // txcontrol[4] = 0x01;

            // Send(XcmpOpcode.PhysUserInput, XcmpType.Request, txcontrol);

            return true;
        }

        public bool SetScan(bool enabled) {
            Log.Debug("Changing scan state");
            byte[] scancontrol = new byte[1];

            scancontrol[0] = (byte) (enabled ? 0x01 : 0x00);

            Send(XcmpOpcode.ScanControl, XcmpType.Request, scancontrol);
            return true;
        }

        public bool SetPower(bool high) {
            Log.Debug("Changing power");
            byte[] powercontrol = new byte[3];

            powercontrol[0] = 0x01;
            powercontrol[1] = 0x00;
            powercontrol[2] = (byte) (high ? 0x03 : 0x00);

            Send(XcmpOpcode.ScanControl, XcmpType.Request, powercontrol);
            return true;
        }

    }
}
