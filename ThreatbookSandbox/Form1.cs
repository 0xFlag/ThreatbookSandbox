using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MaterialSkin;
using System.Reflection;

namespace ThreatbookSandbox
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            //this.label1.Text = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            Assembly asm = Assembly.GetExecutingAssembly();
            AssemblyCopyrightAttribute asmcpr = (AssemblyCopyrightAttribute)Attribute.GetCustomAttribute(asm, typeof(AssemblyCopyrightAttribute));
            this.label2.Text = asmcpr.Copyright;
            this.timer1.Start();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            this.Hide();
            Form2 form2 = new Form2();
            form2.Show();
            timer1.Stop();
        }
    }
}
