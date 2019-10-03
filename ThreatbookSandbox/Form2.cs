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

namespace ThreatbookSandbox
{
    public partial class Form2 : Form
    {
        private ThreatbookScanner iScanner;
        private string iMD5;
        private string iSHA256;
        private string iSHA512;
        private string itag;
        private string peid;
        private string children;
        public Form2()
        {
            InitializeComponent();
            this.comboBox1.SelectedIndex = 0;
        }

        private void Form2_FormClosed(object sender, FormClosedEventArgs e)
        {
            Application.Exit();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            this.textBox1.Text = "f640025957c146a89fd14e714a673426757b812f778f407892aeae6b290a4ec6";
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                MessageBox.Show("*上传文件不要超过 100MB，支持的文件类型包括：PE 可执行文件(EXE、DLL、COM 等)，Office 文档(DOC、XLS、PPT 等)，PDF，HTML，Script，MSI，SWF，JAR，LNK ，ELF，各种压缩包(ZIP、RAR、7Z 等)。");
                if (iScanner == null)
                {
                    if (this.textBox1.Text == "")
                    {
                        this.textBox1.Text = "f640025957c146a89fd14e714a673426757b812f778f407892aeae6b290a4ec6";
                    }
                    iScanner = new ThreatbookScanner(this.textBox1.Text, this.comboBox1.SelectedItem.ToString());
                    iScanner.UseTLS = true;
                    this.textBox1.Enabled = false;
                    this.button1.Enabled = false;
                }
                
                OpenFileDialog ofd = new OpenFileDialog();
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    if (ofd.FileName != "")
                    {
                        this.textBox2.Text = ofd.FileName;
                        iMD5 = ThreatbookScanner.FileHasher.GetMD5(this.textBox2.Text);
                        iSHA256 = ThreatbookScanner.FileHasher.GetSHA256(this.textBox2.Text);
                        iSHA512 = ThreatbookScanner.FileHasher.GetSHA512(this.textBox2.Text);
                        this.label5.Text = iMD5;
                        this.label6.Text = iSHA256;
                        this.label7.Text = iSHA512;
                        this.comboBox1.Enabled = false;
                        this.button4.Enabled = true;
                        this.button5.Enabled = true;
                        this.button6.Enabled = true;
                        this.button8.Enabled = true;
                        post_upload();
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void post_upload()
        {
            try
            {
                ThreatbookScanner.Report Report = new ThreatbookScanner.Report();
                Report = iScanner.GetFileUpload(this.textBox2.Text);
                if (Report.msg == "OK")
                {
                    this.linkLabel1.Text = Report.permalink;
                    this.linkLabel1.Enabled = true;
                    this.button7.Enabled = true;
                    this.button3.Enabled = true;
                }
                else
                {
                    MessageBox.Show(Report.msg);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            try
            {
                ThreatbookScanner.Report Report = new ThreatbookScanner.Report();
                Report = iScanner.GetFileReport(this.label6.Text);
                for (int i = 0; i < Report.data.summary.tag.s.Count; i++)
                {
                    itag = Report.data.summary.tag.s[i];
                }
                this.textBox3.Text =
                    "威胁等级：" + Report.data.summary.threat_level +
                    "\r\n文件名称：" + Report.data.summary.file_name +
                    "\r\n文件类型：" + Report.data.summary.file_type +
                    "\r\nSHA256：" + Report.data.summary.sample_sha256 + 
                    "\r\n沙箱运行环境：" + Report.data.summary.sandbox_type +
                    "\r\n提交时间：" + Report.data.summary.submit_time +
                    "\r\n样本标签：" + itag +
                    "\r\n威胁评分：" + Report.data.summary.threat_score +
                    "\r\n反病毒扫描引擎检出率：" + Report.data.summary.multi_engines;

                this.textBox4.Text =
                    "江民（JiangMin）：" + Report.data.multiengines.JiangMin +
                    "\r\nESET：" + Report.data.multiengines.ESET +
                    "\r\n360（Qihoo 360）：" + Report.data.multiengines.Qihu360 +
                    "\r\nGDATA：" + Report.data.multiengines.GDATA +
                    "\r\n大蜘蛛（Dr.Web）：" + Report.data.multiengines.DrWeb +
                    "\r\nBaidu：" + Report.data.multiengines.Baidu +
                    "\r\nAVG：" + Report.data.multiengines.AVG +
                    "\r\n安天（Antiy）：" + Report.data.multiengines.Antiy +
                    "\r\n熊猫（Panda）：" + Report.data.multiengines.Panda +
                    "\r\nSophos：" + Report.data.multiengines.Sophos +
                    "\r\n小红伞（Avira）：" + Report.data.multiengines.Avira +
                    "\r\n火绒（Huorong）：" + Report.data.multiengines.Huorong +
                    "\r\nIKARUS：" + Report.data.multiengines.IKARUS +
                    "\r\nClamAV：" + Report.data.multiengines.ClamAV +
                    "\r\n金山（Kingsoft）：" + Report.data.multiengines.Kingsoft +
                    "\r\n微软（MSE）：" + Report.data.multiengines.Microsoft +
                    "\r\nBaidu-China：" +
                    "\r\nNANO：" + Report.data.multiengines.NANO +
                    "\r\n卡巴斯基（Kaspersky）：" + Report.data.multiengines.Kaspersky +
                    "\r\n瑞星（Rising）：" + Report.data.multiengines.Rising +
                    "\r\nK7：" + Report.data.multiengines.K7 +
                    "\r\n开维（Kaiwei）：" + Report.data.multiengines.Kaiwei +
                    "\r\nAvast：" + Report.data.multiengines.Avast +
                    "\r\nWebShell专杀：" + Report.data.multiengines.vbwebshell +
                    "\r\n腾讯（Tencent）：" + Report.data.multiengines.Tencent;

                for (int i = 0; i < Report.data.@static.details.pe_basic.peid.Count; i++)
                {
                    peid = Report.data.@static.details.pe_basic.peid[i];
                }
                this.textBox6.Text =
                    "基本信息" +
                    "\r\n样本名称：" + Report.data.@static.basic.sha256 +
                    "\r\n样本类型：" + Report.data.@static.basic.file_type +
                    "\r\n样本大小：" + Report.data.@static.basic.file_size +
                    "\r\nMD5：" + Report.data.@static.basic.md5 +
                    "\r\nSHA1：" + Report.data.@static.basic.sha1 +
                    "\r\nSHA256：" + Report.data.@static.basic.sha256 +
                    "\r\nSSDeep：" + Report.data.@static.basic.ssdeep +
                    "\r\n\r\nPE信息" +
                    "\r\n导入表HASH：" + Report.data.@static.details.pe_basic.import_hash +
                    "\r\n编译时间戳：" + Report.data.@static.details.pe_basic.time_stamp +
                    "\r\nPEID：" + peid +
                    "\r\n入口所在段：" + Report.data.@static.details.pe_basic.entry_point_section +
                    "\r\nPDB信息：" + Report.data.@static.details.pe_basic.pdb_path +
                    "\r\n入口点(OEP)：" + Report.data.@static.details.pe_basic.entry_point +
                    "\r\n镜像基地址：" + Report.data.@static.details.pe_basic.image_base;

                for (int i = 0; i < Report.data.pstree.children.Count; i++)
                {
                    children =
                        "进程 ID：" + Report.data.pstree.children[i].pid +
                        "\r\n进程名称：" + Report.data.pstree.children[i].process_name +
                        "\r\n进程命令符：" + Report.data.pstree.children[i].command_line + 
                        "\r\n" + Report.data.pstree.children[i].first_seen +
                        "\r\n父进程 ID：" + Report.data.pstree.children[i].ppid;
                }
                this.textBox7.Text =
                    "进程详情" +
                    "\r\n" + children +
                    "\r\n" + Report.data.pstree.process_name.cn;

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(this.label5.Text);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(this.label6.Text);
        }

        private void button6_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(this.label7.Text);
        }

        private void button7_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(this.linkLabel1.Text);
        }

        private void linkLabel1_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            try
            {
                System.Diagnostics.Process.Start(this.linkLabel1.Text);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void button8_Click(object sender, EventArgs e)
        {
            this.textBox1.Clear();
            this.textBox1.Enabled = true;
            this.button1.Enabled = true;
            this.textBox2.Clear();
            this.comboBox1.Enabled = true;
            this.button3.Enabled = false;
            this.button4.Enabled = false;
            this.button5.Enabled = false;
            this.button6.Enabled = false;
            this.button7.Enabled = false;
            this.label5.Text = "-";
            this.label6.Text = "-";
            this.label7.Text = "-";
            this.linkLabel1.Text = "-";
            this.textBox3.Clear();
            this.textBox4.Clear();
            this.textBox5.Clear();
            this.textBox6.Clear();
            this.textBox7.Clear();
            this.textBox8.Clear();
            this.textBox9.Clear();
            this.button8.Enabled = false;
        }
    }
}
