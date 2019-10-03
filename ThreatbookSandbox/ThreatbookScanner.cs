using RestSharp;
using RestSharp.Deserializers;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace ThreatbookSandbox
{
    class ThreatbookScanner
    {
        private RestClient rClient;
        private string iAPIKey;
        private bool iUseTLS;
        private string isandbox_type;
        private string run_time;
        public ThreatbookScanner(string APIKey, string sandbox_type)
		{
            rClient = new RestClient();
            rClient.BaseUrl = "http://www.virustotal.com/vtapi/v2/";
            rClient.FollowRedirects = false;
            iAPIKey = APIKey;
            isandbox_type = sandbox_type;
            run_time = "60";
            iUseTLS = true;
        }

        public bool UseTLS
        {
            get
            {
                return iUseTLS;
            }
            set
            {
                iUseTLS = value;
                if (iUseTLS)
                {
                    rClient.BaseUrl = "https://s.threatbook.cn/api/v2/";
                }
                else
                {
                    rClient.BaseUrl = "http://s.threatbook.cn/api/v2/";
                }
            }
        }

        public Report GetFileUpload(string Filename)
        {
            RestRequest Request = new RestRequest();
            Request = new RestRequest("file/upload", Method.POST);
            Request.AddParameter("apikey", iAPIKey);
            Request.AddParameter("sandbox_type", isandbox_type);
            Request.AddParameter("run_time", run_time);
            Request.AddFile("file", Filename);
            return GetReport(Request, true);
        }

        public Report GetFileReport(string Hash)
        {
            RestRequest Request = default(RestRequest);
            Request = new RestRequest("file/report", Method.GET);
            Request.AddParameter("apikey", iAPIKey);
            Request.AddParameter("sandbox_type", isandbox_type);
            Request.AddParameter("sha256", Hash);
            return GetReport(Request, true);
        }

        private Report GetReport(RestRequest Request, bool ApplyHack = false)
        {
            IDeserializer Deserializer = default(IDeserializer);
            Report Report = new Report();
            IRestResponse Response = rClient.Execute(Request);
            if (Response.StatusCode == HttpStatusCode.NoContent)
            {
                throw (new RateLimitException("You have reached the 5 requests pr. min. limit of VirusTotal"));
            }
            if (Response.StatusCode == HttpStatusCode.Forbidden)
            {
                throw (new AccessDeniedException("You don\'t have access to the service. Make sure your API key is working correctly."));
            }
            if (Response.ErrorException != null)
            {
                throw (Response.ErrorException);
            }
            if (Response.StatusCode != HttpStatusCode.OK)
            {
                throw (new Exception("API gave error code " + System.Convert.ToString(Response.StatusCode)));
            }
            if (string.IsNullOrEmpty(Response.Content))
            {
                throw (new Exception("There was no content in the response."));
            }
            if (ApplyHack)
            {
                //   Report = Response.Content.ToString();
                // return Report;
                //MessageBox.Show(Response.Content);
                //Report = GetReport(Request, ApplyHack);

            }
            Deserializer = new JsonDeserializer();
            try
            {
                Report = Deserializer.Deserialize<Report>(Response);
            }
            catch (SerializationException)
            {
                try
                {
                    Report = GetReport(Request, ApplyHack);
                }
                catch (SerializationException ex)
                {
                    throw (new Exception("Failed to deserialize request.", ex));
                }
            }
            return Report;
        }

        public class Report
        {
            private string mmsg;
            private string ssha256;
            private string plink;
            public Data data { get; set; }
            public string msg
            {
                get
                {
                    return mmsg;
                }
                set
                {
                    mmsg = value;
                }
            }

            public string sha256
            {
                get
                {
                    return ssha256;
                }
                set
                {
                    ssha256 = value;
                }
            }

            public string permalink
            {
                get
                {
                    return plink;
                }
                set
                {
                    plink = value;
                }
            }
        }

        public class Data
        {
            /// <summary>
            /// 概要信息
            /// </summary>
            public Summary summary { get; set; }
            /// <summary>
            /// 反病毒扫描引擎检测结果(safe 无检出，e.g Trojan 检出结果)
            /// </summary>
            public Multiengines multiengines { get; set; }
            /// <summary>
            /// 获取文件的静态信息报告 静态信息，以 PE 文件为例
            /// </summary>
            public @static @static { get; set; }
            /// <summary>
            /// 获取文件的进程行为报告
            /// </summary>
            public Pstree pstree { get; set; }
        }

        public class Summary
        {
            /// <summary>
            /// 威胁等级(malicious 恶意, suspicious 可疑, clean 安全)
            /// </summary>
            public string threat_level { get; set; }
            /// <summary>
            /// 文件提交时间
            /// </summary>
            public string submit_time { get; set; }
            /// <summary>
            /// 文件名称
            /// </summary>
            public string file_name { get; set; }
            /// <summary>
            /// 文件类型
            /// </summary>
            public string file_type { get; set; }
            /// <summary>
            /// 文件的 Hash 值
            /// </summary>
            public string sample_sha256 { get; set; }
            /// <summary>
            /// 标签
            /// </summary>
            public Tag tag { get; set; }
            /// <summary>
            /// 威胁评分 60-100分，判为恶意 30-59分，判为可疑 0-29分，判为正常
            /// </summary>
            public int threat_score { get; set; }
            /// <summary>
            /// 沙箱运行环境
            /// </summary>
            public string sandbox_type { get; set; }
            /// <summary>
            /// 反病毒扫描引擎检出率
            /// </summary>
            public string multi_engines { get; set; }
        }

        public class Tag
        {
            /// <summary>
            /// 静态标签
            /// </summary>
            public List<string> s { get; set; }
            /// <summary>
            /// 检测标签
            /// </summary>
            public List<string> x { get; set; }
        }

        public class Multiengines
        {
            /// <summary>
            /// 
            /// </summary>
            public string Tencent { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string vbwebshell { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Avast { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Kaiwei { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string K7 { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Rising { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Kaspersky { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string NANO { get; set; }
            /// <summary>
            ///
            /// </summary>
            //public string Baidu-China { get; set; }
            /// <summary>
            ///
            /// </summary>
            public string Microsoft { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Kingsoft { get; set; }
            /// <summary> 
            /// 
            /// </summary>
            public string ClamAV { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string IKARUS { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Huorong { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Avira { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Sophos { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Panda { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Antiy { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string AVG { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Baidu { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string DrWeb { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string GDATA { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string Qihu360 { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string ESET { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string JiangMin { get; set; }
        }

        public class @static
        {
            /// <summary>
            /// 
            /// </summary>
            public Details details { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public Basic basic { get; set; }
        }

        public class Details
        {
            /// <summary>
            /// PE 文件版本信息
            /// </summary>
            /// public List<Pe_version_infoItem> pe_version_info { get; set; }
            /// <summary>
            /// PE 文件节表信息
            /// </summary>
            ///  public List<Pe_sectionsItem> pe_sections { get; set; }
            /// <summary>
            /// PE 文件签名信息
            /// </summary>
            /// public Pe_signatures pe_signatures { get; set; }
            /// <summary>
            /// PE 文件导入表信息
            /// </summary>
            /// public List<Pe_importsItem> pe_imports { get; set; }
            /// <summary>
            /// PE 文件资源信息
            /// </summary>
            /// public List<Pe_resourcesItem> pe_resources { get; set; }
            /// <summary>
            /// PE 文件静态标签
            /// </summary>
            /// public List<string> tag { get; set; }
            /// <summary>
            /// PE 文件第三方检测信息
            /// </summary>
            public Pe_basic pe_basic { get; set; }
            /// <summary>
            /// PE 文件基本信息
            /// </summary>
            //public Pe_detect pe_detect { get; set; }
            /// <summary>
            /// PE 文件导出表信息
            /// </summary>
            public List<string> pe_exports { get; set; }
        }

        public class Pe_basic
        {
            /// <summary>
            /// 
            /// </summary>
            /// public Tls_info tls_info { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string import_hash { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string time_stamp { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public List<string> peid { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string entry_point_section { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string pdb_path { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string entry_point { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string image_base { get; set; }
        }

        public class Basic
        {
            /// <summary>
            /// 
            /// </summary>
            public string sha1 { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string sha256 { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string file_type { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string file_name { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string ssdeep { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public int file_size { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public string md5 { get; set; }
        }

        public class Pstree
        {
            /// <summary>
            /// 
            /// </summary>
            public List<ChildrenItem> children { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public Process_name process_name { get; set; }
        }

        public class Process_name
        {
            /// <summary>
            /// 
            /// </summary>
            public string en { get; set; }
            /// <summary>
            ///
            /// </summary>
            public string cn { get; set; }
        }

        public class ChildrenItem
        {
            /// <summary>
            /// 
            /// </summary>
            public string track { get; set; }
            /// <summary>
            /// 进程 ID
            /// </summary>
            public int pid { get; set; }
            /// <summary>
            /// 进程名称
            /// </summary>
            public string process_name { get; set; }
            /// <summary>
            /// 进程命令符
            /// </summary>
            public string command_line { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public double first_seen { get; set; }
            /// <summary>
            /// 
            /// </summary>
            public int ppid { get; set; }
            /// <summary>
            /// 父进程 ID
            /// </summary>
            public List<string> children { get; set; }
        }

        public class FileHasher
        {
            public static string GetSHA256(string Filename)
            {
                SHA256CryptoServiceProvider SHA256 = default(SHA256CryptoServiceProvider);
                FileStream FileStream = default(FileStream);
                SHA256 = new SHA256CryptoServiceProvider();
                FileStream = new FileStream(Filename, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Write | FileShare.Delete, 8192);
                SHA256.ComputeHash(FileStream);
                FileStream.Close();
                return ByteArrayToString(SHA256.Hash);
            }
            public static string GetSHA512(string Filename)
            {
                SHA512CryptoServiceProvider SHA512 = default(SHA512CryptoServiceProvider);
                FileStream FileStream = default(FileStream);
                SHA512 = new SHA512CryptoServiceProvider();
                FileStream = new FileStream(Filename, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Write | FileShare.Delete, 8192);
                SHA512.ComputeHash(FileStream);
                FileStream.Close();
                return ByteArrayToString(SHA512.Hash);
            }
            public static string GetMD5(string Filename)
            {
                MD5CryptoServiceProvider MD5 = default(MD5CryptoServiceProvider);
                FileStream FileStream = default(FileStream);
                MD5 = new MD5CryptoServiceProvider();
                FileStream = new FileStream(Filename, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Write | FileShare.Delete, 8192);
                MD5.ComputeHash(FileStream);
                FileStream.Close();
                return ByteArrayToString(MD5.Hash);
            }
            private static string ByteArrayToString(byte[] Data)
            {
                StringBuilder Builder = default(StringBuilder);
                Builder = new StringBuilder(Data.Length * 2);
                foreach (byte B in Data)
                {
                    Builder.AppendFormat("{0:x2}", B);
                }
                return Builder.ToString().ToLower();
            }
        }

        public class AccessDeniedException : Exception
        {
            public AccessDeniedException(string Message)
                : base(Message)
            {
            }
        }

        public class RateLimitException : Exception
        {
            public RateLimitException(string Message)
                : base(Message)
            {
            }
        }
    }
}
