using daemon;
using FFmpeg.AutoGen;
using rc2_core;
using Serilog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace moto_xcmp
{
    public enum XcmpFlavor {
        ASTRO = 0,
        //TRBO = 1  // not supported yet
    }
    
    public class MotoXcmpConfig
    {
        public string Ip = "";
        public int Port = 0;
        public uint AuthKey0 = 0;
        public uint AuthKey1 = 0;
        public uint AuthKey2 = 0;
        public uint AuthKey3 = 0;
        public uint AuthDelta = 0;
        public int AuthLevel = 0;
        public XcmpFlavor Flavor = XcmpFlavor.ASTRO;
    }

    public class MotoXcmpRadio : rc2_core.Radio
    {
        private XCMP Xcmp;


        /// <summary>
        /// Initialize a new Motorola SB9600 radio
        /// </summary>
        /// <param name="name">Radio name</param>
        /// <param name="desc">Radio description</param>
        /// <param name="rxOnly">Whether radio is rx-only or not</param>
        /// <param name="listenAddress">daemon listen address</param>
        /// <param name="listenPort">daemon list port</param>
        /// <param name="serialPortName">Serial port name for SB9600</param>
        /// <param name="headType">SB9600 head type</param>
        /// <param name="rxLeds">Whether to use the RX leds on the control head as an RX status indicator</param>
        /// <param name="softkeys">list of softkeys</param>
        /// <param name="zoneLookups">list of zone text lookups</param>
        /// <param name="chanLookups">list of channel text lookups</param>
        /// <param name="txAudioCallback">callback for tx audio samples</param>
        /// <param name="txAudioSampleRate">samplerate for tx audio</param>
        public MotoXcmpRadio(
            string name, string desc, bool rxOnly,
            IPAddress listenAddress, int listenPort,
            string radioIP, int radioPort,
            uint radioAuthKey0, uint radioAuthKey1, uint radioAuthKey2, uint radioAuthKey3, uint radioAuthDelta,
            int radioAuthLevel, XcmpFlavor radioXcmpFlavor,
            Action<short[]> txAudioCallback, int txAudioSampleRate,
            List<rc2_core.SoftkeyName> softkeys,
            List<rc2_core.TextLookup> zoneLookups = null, List<rc2_core.TextLookup> chanLookups = null
            ) : base(name, desc, rxOnly, listenAddress, listenPort, softkeys, zoneLookups, chanLookups, txAudioCallback, txAudioSampleRate)
        {
            // // Save softkey lookups
            // this.softkeyBindings = softkeyBindings;
            // // Init SB9600
            // sb9600 = new SB9600(serialPortName, headType, this.softkeyBindings, this, rxLeds);
            // sb9600.StatusCallback += () => {
            //     this.RadioStatusCallback();
            // };
            Xcmp = new XCMP(radioIP, radioPort, true, this, new uint[]{radioAuthKey0, radioAuthKey1, radioAuthKey2, radioAuthKey3}, radioAuthDelta, (byte) radioAuthLevel);
        }

        /// <summary>
        /// Start the base radio as well as the SB9600 services
        /// </summary>
        /// <param name="reset"></param>
        public override void Start(bool reset = false)
        {
            Log.Information($"Starting new Motorola SB9600 radio instance");
            base.Start(reset);
            Xcmp.Start();
        }

        /// <summary>
        /// Stop the base radio as well as the SB9600 services
        /// </summary>
        public new void Stop()
        {
            base.Stop();
            Xcmp.Stop();
        }

        public override bool ChangeChannel(bool down)
        {
            return Xcmp.ChangeChannel(down);
        }

        public override bool SetTransmit(bool tx)
        {
            return Xcmp.SetTransmit(tx);
        }

        public override bool PressButton(rc2_core.SoftkeyName name)
        {
            return true; //sb9600.PressButton(name);
        }

        public override bool ReleaseButton(rc2_core.SoftkeyName name)
        {
            return true; //sb9600.ReleaseButton(name);
        }

    }
}
