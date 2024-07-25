using log4net;
using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace XML_Parse
{
    class LogEntry
    {
        public DateTime Timestamp { get; set; }
        public String Dataset { get; set; }
        public String ThreadId { get; set; }
        public String LogLevel { get; set; }
        public String ErrorMessage { get; set; }
    }

    internal class Program
    {
        private static readonly ILog log = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
        public static StringBuilder msgBuilder = new StringBuilder();

        static void Main(String[] args)
        {
            try
            {
                int wgscount = 0;
                int dscount = 0;
                msgBuilder.Append("<style>#security {width: 100%;border-radius:10px;border-spacing: 0;font-family:'Trebuchet MS', sans-serif;}#security td, #security th {border: 1px solid #ddd;padding: 10px;}#security tr:nth-child(even){background-color: #f2f2f2;}#security th {padding-top: 12px;padding-bottom: 12px;text-align: center;background-color: #5F9EA0;color: white;}</style><body style=\"font-family:'Trebuchet MS', sans-serif;\">");
                msgBuilder.Append("Dear Admin,</br>Below is the summary of Content Manager Monitoring Tool on " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " </br></br>");
                msgBuilder.Append("<table id='security' border='2'><tr><th>Environment</th><th>Servers</th><th>Services</th><th>CM Components</th><th>Monitoring Components</th><th>Status</th>");
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.Load("CM_Monitor.xml");
                XmlElement root = xmlDoc.DocumentElement;
                foreach (XmlElement environmentNode in root.SelectNodes("CM_Monitor/Environments/Environment"))
                {
                    msgBuilder.Append("<tr><td rowspan=\"EnviCount\">" + environmentNode.GetAttribute("name") + "</td>");
                    log.Info($"Environment: {environmentNode.GetAttribute("name")}");
                    foreach (XmlElement workgroupNode in environmentNode.SelectNodes("WorkgroupServers/Workgroup"))
                    {
                        wgscount += 1;
                        msgBuilder.Append("<td rowspan=\"11\">" + workgroupNode.GetAttribute("name") + "</td><td rowspan=\"6\">CM Services</td>");
                        log.Info($"  Workgroup: {workgroupNode.GetAttribute("name")}, Prop: {workgroupNode.GetAttribute("prop")}");
                        foreach (XmlElement serviceNode in workgroupNode.SelectNodes("Services/service"))
                        {
                            if (serviceNode.GetAttribute("name") == "WGS" && serviceNode.GetAttribute("prop") != "")
                            {
                                CheckService(serviceNode.GetAttribute("prop"), "WGS");
                            }
                            else if (serviceNode.GetAttribute("name") == "IDOL" && serviceNode.GetAttribute("prop") != "")
                            {
                                CheckService(serviceNode.GetAttribute("prop"), "IDOL");
                            }
                            else if (serviceNode.GetAttribute("name") == "IDOLContent" && serviceNode.GetAttribute("prop") != "")
                            {
                                CheckService(serviceNode.GetAttribute("prop"), "IDOL Content");
                            }
                            else if (serviceNode.GetAttribute("name") == "ServiceAPIBulk" && serviceNode.GetAttribute("prop") != "")
                            {
                                CheckService(serviceNode.GetAttribute("prop"), "Service API Bulk");
                            }
                            else if (serviceNode.GetAttribute("name") == "OnstreamDataprovider" && serviceNode.GetAttribute("prop") != "")
                            {
                                CheckService(serviceNode.GetAttribute("prop"), "OnStream Data Provider");
                            }
                            else if (serviceNode.GetAttribute("name") == "EmailLinkService" && serviceNode.GetAttribute("prop") != "")
                            {
                                CheckService(serviceNode.GetAttribute("prop"), "Email Link");
                            }
                            else
                            {
                                msgBuilder.Append("</tr><tr>");
                            }
                        }
                        msgBuilder.Append("<td rowspan=\"5\">CM Logs</td>");
                        foreach (XmlElement logPathNode in workgroupNode.SelectNodes("LogPaths/Path"))
                        {
                            if (logPathNode.GetAttribute("name") == "WGSLogs" && logPathNode.GetAttribute("path") != "")
                            {
                                CheckWGSLogs(logPathNode.GetAttribute("path"), "WGSLogs", logPathNode.GetAttribute("lastupdated"), environmentNode.GetAttribute("name"), workgroupNode.GetAttribute("name"));
                            }
                            else if (logPathNode.GetAttribute("name") == "ServiceAPILogs" && logPathNode.GetAttribute("path") != "")
                            {
                                CheckLogs(logPathNode.GetAttribute("path"), "ServiceAPILogs", logPathNode.GetAttribute("lastupdated"), environmentNode.GetAttribute("name"), workgroupNode.GetAttribute("name"));
                            }
                            else if (logPathNode.GetAttribute("name") == "WebClientLogs" && logPathNode.GetAttribute("path") != "")
                            {
                                CheckLogs(logPathNode.GetAttribute("path"), "WebClientLogs", logPathNode.GetAttribute("lastupdated"), environmentNode.GetAttribute("name"), workgroupNode.GetAttribute("name"));
                            }
                            else if (logPathNode.GetAttribute("name") == "WebDrawerLogs" && logPathNode.GetAttribute("path") != "")
                            {
                                CheckLogs(logPathNode.GetAttribute("path"), "WebDrawerLogs", logPathNode.GetAttribute("lastupdated"), environmentNode.GetAttribute("name"), workgroupNode.GetAttribute("name"));
                            }
                            else if (logPathNode.GetAttribute("name") == "LDAPLogs" && logPathNode.GetAttribute("path") != "")
                            {
                                CheckLDAPLogs(logPathNode.GetAttribute("path"), "LDAPLogs", logPathNode.GetAttribute("lastupdated"), environmentNode.GetAttribute("name"), workgroupNode.GetAttribute("name"));
                            }
                            else
                            {
                                msgBuilder.Append("</tr><tr>");
                            }
                        }
                    }
                    foreach (XmlElement datasetNode in environmentNode.SelectNodes("Datasets/Dataset"))
                    {
                        dscount += 1;
                        msgBuilder.Append("<td rowspan=\"3\">" + datasetNode.GetAttribute("name") + " : " + datasetNode.GetAttribute("id") + "</td>");
                        log.Info($"  Dataset: {datasetNode.GetAttribute("name")}, ID: {datasetNode.GetAttribute("id")}");
                        foreach (XmlElement urlNode in datasetNode.SelectNodes("urls/url"))
                        {
                            if (urlNode.GetAttribute("name") == "CMWeb" && urlNode.GetAttribute("path") != "")
                            {
                                CheckWebClient(urlNode.GetAttribute("path"), "Web Client");
                            }
                            else if (urlNode.GetAttribute("name") == "CMServiceAPI" && urlNode.GetAttribute("path") != "")
                            {
                                CheckWebClient(urlNode.GetAttribute("path"), "Service API");
                            }
                            else if (urlNode.GetAttribute("name") == "CMWebDrawer" && urlNode.GetAttribute("path") != "")
                            {
                                CheckWebClient(urlNode.GetAttribute("path"), "Web Drawer");
                            }
                            else
                            {
                                msgBuilder.Append("</tr><tr>");
                            }
                        }
                    }
                    int totalcount = (wgscount * 11) + (dscount * 3);
                    msgBuilder.Replace("EnviCount", totalcount + "");
                }
                foreach (XmlElement windowsnode in root.SelectNodes("CM_Monitor/WindowsEvent"))
                {
                    foreach (XmlElement servicesnode in windowsnode.SelectNodes("Services"))
                    {
                        DateTime lastupdated = DateTime.Now.AddDays(-5);
                        if (servicesnode.GetAttribute("lastupdated") != "")
                        {
                            lastupdated = DateTime.ParseExact(servicesnode.GetAttribute("lastupdated"), "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                        }
                        EventViewerLog("Application", servicesnode.GetAttribute("name"), lastupdated);
                    }
                }
                msgBuilder.Length = msgBuilder.Length - 4;
                msgBuilder.Append("</body></table>");
                foreach (XmlElement emailNode in root.SelectNodes("CM_Monitor/EmailSetup"))
                {
                    if (emailNode.GetAttribute("Enabled") == "False")
                    {
                        String reptfolder = Path.Combine(Environment.CurrentDirectory, "Reports");
                        if (!Directory.Exists(reptfolder))
                        {
                            Directory.CreateDirectory(reptfolder);
                        }
                        String mailfile = Path.Combine(reptfolder, "EmailOutput-" + DateTime.Now.ToString("ddMMyyyyHHmmss") + ".html");
                        using (StreamWriter sw = new StreamWriter(mailfile, false))
                        {
                            sw.WriteLine(msgBuilder + "");
                        }
                        break;
                    }
                    foreach (XmlElement recipientsNode in emailNode.SelectNodes("Recipients"))
                    {
                        SendMail(emailNode.GetAttribute("From"), recipientsNode.GetAttribute("To"), emailNode.GetAttribute("Subject"), emailNode.GetAttribute("SmtpServer"), Convert.ToInt16(emailNode.GetAttribute("SmtpPort")));
                    }
                }
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public void CheckService(String ServiceName, String Service)
        {
            try
            {
                ServiceController sc = new ServiceController(ServiceName);
                log.Info($"   CM " + Service + " Service '" + sc.ServiceName + "' is " + sc.Status);
                String color = sc.Status.ToString() != "Running" ? "Salmon" : "MediumSeaGreen";
                msgBuilder.Append("<td>CM " + Service + "</td><td>" + sc.ServiceName + "</td><td bgcolor=\"" + color + "\">" + sc.Status + "</td></tr><tr>");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public void CheckWebClient(String URL, String Service)
        {
            int status = 0;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(URL);
            X509Certificate cert2 = null;
            try
            {
                HttpWebResponse responses = (HttpWebResponse)request.GetResponse();
                X509Certificate cert = request.ServicePoint.Certificate;
                cert2 = new X509Certificate2(cert);
            }
            catch
            {
                X509Certificate cert = request.ServicePoint.Certificate;
                if (cert != null)
                {
                    cert2 = new X509Certificate2(cert);
                }
                else
                {
                    status = 1;
                    log.Info(String.Format("No SSL Certificate Available for : {0}", URL));
                    msgBuilder.Append("<td>" + Service + "</td><td>" + URL + "</td><td>" + Service + "</td><td bgcolor=\"statuscolor\">No SSL Certificate Available, ");
                }
            }
            if (cert2 != null)
            {
                TimeSpan timeSpan = Convert.ToDateTime(cert2.GetExpirationDateString()) - DateTime.Now;
                Console.WriteLine("SSL Certificate is valid till : " + cert2.GetExpirationDateString() + " for " + URL + " " + timeSpan.Days + " Days Remaining");
                msgBuilder.Append("<td>" + Service + "</td><td>" + URL + "</td><td>" + Service + "</td><td bgcolor=\"statuscolor\">SSL Certificate is valid till : " + cert2.GetExpirationDateString() + "</td><td>" + timeSpan.Days + " Days Remaining, ");
            }

            try
            {
                var myRequest = (HttpWebRequest)WebRequest.Create(URL);
                myRequest.UseDefaultCredentials = myRequest.PreAuthenticate = true;
                myRequest.Credentials = CredentialCache.DefaultCredentials;
                var response = (HttpWebResponse)myRequest.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK)
                {
                    log.Info(String.Format(Service + " '{0}' Available", URL));
                    msgBuilder.Append("URL is Available</td></tr><tr>");
                }
                else
                {
                    status = 1;
                    log.Info(String.Format(Service + " '{0}' Returned, but with status: {1}", URL, response.StatusDescription));
                    msgBuilder.Append("URL Returned, but with status: " + response.StatusDescription + "</td></tr><tr>");
                }
            }
            catch (Exception ex)
            {
                status = 1;
                log.Error(String.Format(Service + " '{0}' unavailable: {1}", URL, ex.Message));
                msgBuilder.Append("URL is Unavailable</td></tr><tr>");
            }
            if (status == 0)
            {
                msgBuilder.Replace("statuscolor", "MediumSeaGreen");
            }
            else
            {
                msgBuilder.Replace("statuscolor", "Salmon");
            }
        }

        static public void CheckLogs(String path, String Service, String time, String Environment, String WGS)
        {
            try
            {
                DataTable dt = new DataTable();
                dt.Columns.Add("First_Occurance");
                dt.Columns.Add("Last_Occurance");
                dt.Columns.Add("Error");
                dt.Columns.Add("Count");
                List<String[]> rows = new List<String[]>();
                DateTime last = DateTime.Now;
                DirectoryInfo folder = new DirectoryInfo(path);
                var files = folder.GetFiles().Where(file => file.Name.Equals("log-file.txt", StringComparison.OrdinalIgnoreCase) && file.LastWriteTime < last);
                if (!String.IsNullOrEmpty(time))
                {
                    last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                    files = folder.GetFiles().Where(file => file.Name.Equals("log-file.txt", StringComparison.OrdinalIgnoreCase) && file.LastWriteTime > last);
                }
                object dtLock = new object();
                object rowsLock = new object();
                Parallel.ForEach(files, file =>
                {
                    FileStream fs = new FileStream(Path.Combine(path, file.Name), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    StreamReader sr = new StreamReader(fs, Encoding.Default);
                    String logLines = sr.ReadToEnd();
                    String pattern = @"^(?<Timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\,\d{3})\s\[(?<ThreadId>\d+)\]\s(?<LogLevel>\w+)\s(?<ErrorMessage>.+)$";
                    List<LogEntry> logEntries = new List<LogEntry>();
                    MatchCollection matches = Regex.Matches(logLines, pattern, RegexOptions.Multiline);
                    foreach (Match match in matches)
                    {
                        LogEntry logEntry = new LogEntry
                        {
                            Timestamp = DateTime.ParseExact(match.Groups["Timestamp"].Value, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture),
                            ThreadId = match.Groups["ThreadId"].Value,
                            LogLevel = match.Groups["LogLevel"].Value,
                            ErrorMessage = match.Groups["ErrorMessage"].Value
                        };
                        if (logEntry.LogLevel == "ERROR")
                        {
                            if (!String.IsNullOrEmpty(time))
                            {
                                DateTime lastupdated = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                                if (logEntry.Timestamp < lastupdated)
                                {
                                    continue;
                                }
                            }
                            logEntries.Add(logEntry);
                        }
                    }
                    lock (dtLock)
                    {
                        foreach (var entry in logEntries)
                        {
                            log.Info($"Timestamp: {entry.Timestamp}, ThreadId: {entry.ThreadId}, LogLevel: {entry.LogLevel}, ErrorMessage: {entry.ErrorMessage.Trim()}");
                            String[] row = { entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), Environment, WGS, "", entry.ThreadId, entry.LogLevel, entry.ErrorMessage.Trim() };
                            lock (rowsLock)
                            {
                                rows.Add(row);
                            }
                            int flag = 0;
                            for (int i = 0; i < dt.Rows.Count; i++)
                            {
                                if (dt.Rows[i][2].ToString() == entry.ErrorMessage.Trim())
                                {
                                    DateTime first = DateTime.ParseExact(dt.Rows[i][0] + "", "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                    if (first > entry.Timestamp)
                                    {
                                        dt.Rows[i][0] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    else
                                    {
                                        dt.Rows[i][1] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    int count = int.Parse(dt.Rows[i][3] + "");
                                    dt.Rows[i][3] = count + 1;
                                    flag = 1;
                                    break;
                                }
                            }
                            if (flag == 0)
                            {
                                dt.Rows.Add(entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.ErrorMessage.Trim(), 1);
                            }
                        }
                    }
                });
                UpdateXML(Service, Environment, WGS, rows, dt);
                String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                msgBuilder.Append("<td>" + Service + "</td><td>" + Service + "</td><td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + last.ToString("yyyy-MM-dd HH:mm:ss,fff") + "</td></tr><tr>");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public void CheckWGSLogs(String path, String Service, String time, String Environment, String WGS)
        {
            try
            {
                DataTable dt = new DataTable();
                dt.Columns.Add("First_Occurance");
                dt.Columns.Add("Last_Occurance");
                dt.Columns.Add("Error");
                dt.Columns.Add("Count");
                List<String[]> rows = new List<String[]>();
                DateTime last = DateTime.Now;
                DirectoryInfo folder = new DirectoryInfo(path);
                var files = folder.GetFiles().Where(file => file.Name.StartsWith("TRIMWorkgroup") && file.LastWriteTime < last && file.Extension == ".log");
                if (!String.IsNullOrEmpty(time))
                {
                    last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                    files = folder.GetFiles().Where(file => file.Name.StartsWith("TRIMWorkgroup") && file.LastWriteTime > last && file.Extension == ".log");
                }
                object dtLock = new object();
                object rowsLock = new object();
                Parallel.ForEach(files, file =>
                {
                    FileStream fs = new FileStream(Path.Combine(path, file.Name), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    StreamReader sr = new StreamReader(fs, Encoding.Default);
                    String logLines = sr.ReadToEnd();
                    String pattern = @"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<Dataset>\w+)\s+(?<UnknownField>\d+)\s+(?<UnknownField2>\d+)\s+(?<LogLevel>\w+):\s+(?<ErrorMessage>.+)$";
                    List<LogEntry> logEntries = new List<LogEntry>();
                    MatchCollection matches = Regex.Matches(logLines, pattern, RegexOptions.Multiline);
                    foreach (Match match in matches)
                    {
                        LogEntry logEntry = new LogEntry
                        {
                            Timestamp = DateTime.ParseExact(file.CreationTime.ToString("yyyy-MM-dd") + " " + match.Groups["Timestamp"].Value, "yyyy-MM-dd HH:mm:ss:fff", CultureInfo.InvariantCulture),
                            Dataset = match.Groups["Dataset"].Value,
                            ThreadId = match.Groups["ThreadId"].Value,
                            LogLevel = match.Groups["LogLevel"].Value,
                            ErrorMessage = match.Groups["ErrorMessage"].Value
                        };
                        if (logEntry.LogLevel == "Error")
                        {
                            if (!String.IsNullOrEmpty(time))
                            {
                                DateTime lastupdated = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                                if (logEntry.Timestamp < lastupdated)
                                {
                                    continue;
                                }
                            }
                            logEntries.Add(logEntry);
                        }
                    }
                    lock (dtLock)
                    {
                        foreach (var entry in logEntries)
                        {
                            log.Info($" Timestamp = {file.LastWriteTime.ToString("yyyy-MM-dd") + " " + entry.Timestamp.ToString("HH:mm:ss,fff")}, Dataset = \"{entry.Dataset}\", ThreadId = {entry.ThreadId}, LogLevel = \"{entry.LogLevel}\", ErrorMessage = \"{entry.ErrorMessage.Trim()}\"");
                            String[] row = { entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), Environment, WGS, entry.Dataset, entry.ThreadId, entry.LogLevel, entry.ErrorMessage.Trim() };
                            lock (rowsLock)
                            {
                                rows.Add(row);
                            }
                            int flag = 0;
                            for (int i = 0; i < dt.Rows.Count; i++)
                            {
                                if (dt.Rows[i][2].ToString() == entry.ErrorMessage.Trim())
                                {
                                    DateTime first = DateTime.ParseExact(dt.Rows[i][0] + "", "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                    if (first > entry.Timestamp)
                                    {
                                        dt.Rows[i][0] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    else
                                    {
                                        dt.Rows[i][1] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    int count = int.Parse(dt.Rows[i][3] + "");
                                    dt.Rows[i][3] = count + 1;
                                    flag = 1;
                                    break;
                                }
                            }
                            if (flag == 0)
                            {
                                dt.Rows.Add(entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.ErrorMessage.Trim(), 1);
                            }
                        }
                    }
                });
                String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                msgBuilder.Append("<td>" + Service + "</td><td>" + Service + "</td><td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + last.ToString("yyyy-MM-dd HH:mm:ss,fff") + "</td></tr><tr>");
                UpdateXML(Service, Environment, WGS, rows, dt);
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public void EventViewerLog(String logName, String sourceName, DateTime lastdate)
        {
            try
            {
                DataTable dt = new DataTable();
                dt.Columns.Add("First_Occurance");
                dt.Columns.Add("Last_Occurance");
                dt.Columns.Add("Error");
                dt.Columns.Add("Count");
                List<String[]> rows = new List<String[]>();
                EventLog eventLog = new EventLog(logName);
                object dtLock = new object();
                object rowsLock = new object();
                Parallel.ForEach(eventLog.Entries.Cast<EventLogEntry>(), entry =>
                {
                    if (entry.Source.Equals(sourceName, StringComparison.OrdinalIgnoreCase) && entry.EntryType == EventLogEntryType.Error && entry.TimeGenerated >= lastdate)
                    {
                        log.Info($"Event ID : " + entry.InstanceId + "\t Entry Type: " + entry.EntryType + "\t Source : " + entry.Source + "\t Message: " + entry.Message.Replace("\r\n", " : ") + "\t Time Generated: " + entry.TimeGenerated);
                        String[] row = { entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff"), "Event Viewer", "", entry.Source, entry.InstanceId + "", entry.EntryType + "", entry.Message.Replace("\r\n", " : ") };
                        lock (rowsLock)
                        {
                            rows.Add(row);
                        }
                        lock (dtLock)
                        {
                            int flag = 0;
                            for (int i = 0; i < dt.Rows.Count; i++)
                            {
                                if (dt.Rows[i][2].ToString() == entry.Message.Replace("\r\n", " : "))
                                {
                                    DateTime first = DateTime.ParseExact(dt.Rows[i][0] + "", "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                    if (first > entry.TimeGenerated)
                                    {
                                        dt.Rows[i][0] = entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    else
                                    {
                                        dt.Rows[i][1] = entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    int count = int.Parse(dt.Rows[i][3] + "");
                                    dt.Rows[i][3] = count + 1;
                                    flag = 1;
                                    break;
                                }
                            }
                            if (flag == 0)
                            {
                                dt.Rows.Add(entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.TimeGenerated.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Message.Replace("\r\n", " : "), 1);
                            }
                        }
                    }
                });
                String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                msgBuilder.Append("<td></td><td></td><td>Event Viewer Logs</td><td>" + sourceName + "</td><td>Windows Event Logs</td><td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + lastdate.ToString("dd-MM-yyyy HH:mm:ss.fff") + "</td></tr><tr>");
                XDocument xmlDoc = XDocument.Load("CM_Monitor.xml");
                var target = xmlDoc.Elements("Root").Elements("CM_Monitor").Elements("WindowsEvent").Elements("Services").Where(e => e.Attribute("name").Value == sourceName).Single();
                target.Attribute("lastupdated").Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss,fff");
                xmlDoc.Save("CM_Monitor.xml");
                UpdateXML("", "", "", rows, dt);
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public void CheckLDAPLogs(String path, String Service, String time, String Environment, String WGS)
        {
            try
            {
                DataTable dt = new DataTable();
                dt.Columns.Add("First_Occurance");
                dt.Columns.Add("Last_Occurance");
                dt.Columns.Add("Error");
                dt.Columns.Add("Count");
                List<String[]> rows = new List<String[]>();
                DateTime last = DateTime.Now;
                DirectoryInfo folder = new DirectoryInfo(path);
                var files = folder.GetFiles().Where(file => file.LastWriteTime < last);
                if (!String.IsNullOrEmpty(time))
                {
                    last = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                    files = folder.GetFiles().Where(file => file.LastWriteTime > last);
                }
                object dtLock = new object();
                object rowsLock = new object();
                Parallel.ForEach(files, file =>
                {
                    FileStream fs = new FileStream(path + "\\" + file.Name, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    StreamReader sr = new StreamReader(fs, Encoding.Default);
                    String logLines = sr.ReadToEnd();
                    String pattern = @"^(?<Timestamp>\d{2}:\d{2}:\d{2}:\d{3})\s+(?<ThreadId>\d+)\s+(?<LogLevel>--|-\w+-|-\w+-|\*)\s+(?<ErrorMessage>.+)$";
                    List<LogEntry> logEntries = new List<LogEntry>();
                    MatchCollection matches = Regex.Matches(logLines, pattern, RegexOptions.Multiline);
                    foreach (Match match in matches)
                    {
                        LogEntry logEntry = new LogEntry
                        {
                            Timestamp = DateTime.ParseExact(file.CreationTime.ToString("yyyy-MM-dd") + " " + match.Groups["Timestamp"].Value, "yyyy-MM-dd HH:mm:ss:fff", CultureInfo.InvariantCulture),
                            ThreadId = match.Groups["ThreadId"].Value,
                            LogLevel = match.Groups["LogLevel"].Value,
                            ErrorMessage = match.Groups["ErrorMessage"].Value
                        };
                        if (logEntry.ErrorMessage.StartsWith("Failed"))
                        {
                            if (!String.IsNullOrEmpty(time))
                            {
                                DateTime lastupdated = DateTime.ParseExact(time, "yyyy-MM-dd HH:mm:ss,fff", CultureInfo.InvariantCulture);
                                if (logEntry.Timestamp < lastupdated)
                                {
                                    continue;
                                }
                            }
                            logEntries.Add(logEntry);
                        }
                    }
                    foreach (var entry in logEntries)
                    {
                        log.Info($" Timestamp = {file.LastWriteTime.ToString("yyyy-MM-dd") + " " + entry.Timestamp.ToString("HH:mm:ss,fff")}, Dataset = \"{entry.Dataset}\", ThreadId = {entry.ThreadId}, LogLevel = \"{entry.LogLevel}\", ErrorMessage = \"{entry.ErrorMessage.Trim()}\"");
                        String[] row = { entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), Environment, WGS, entry.Dataset, entry.ThreadId, entry.LogLevel, entry.ErrorMessage.Trim() };
                        lock (rowsLock)
                        {
                            rows.Add(row);
                        }
                        lock (dtLock)
                        {
                            int flag = 0;
                            for (int i = 0; i < dt.Rows.Count; i++)
                            {
                                if (dt.Rows[i][2].ToString() == entry.ErrorMessage.Trim())
                                {
                                    DateTime first = DateTime.ParseExact(dt.Rows[i][0].ToString(), "dd-MM-yyyy HH:mm:ss.fff", CultureInfo.InvariantCulture);
                                    if (first > entry.Timestamp)
                                    {
                                        dt.Rows[i][0] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    else
                                    {
                                        dt.Rows[i][1] = entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff");
                                    }
                                    int count = int.Parse(dt.Rows[i][3].ToString());
                                    dt.Rows[i][3] = count + 1;
                                    flag = 1;
                                    break;
                                }
                            }
                            if (flag == 0)
                            {
                                dt.Rows.Add(entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.Timestamp.ToString("dd-MM-yyyy HH:mm:ss.fff"), entry.ErrorMessage.Trim(), 1);
                            }
                        }
                    }
                });
                String color = rows.Count == 0 ? "MediumSeaGreen" : "Salmon";
                msgBuilder.Append("<td>" + Service + "</td><td>" + Service + "</td><td bgcolor=\"" + color + "\">" + rows.Count + " Errors Found, " + last.ToString("yyyy-MM-dd HH:mm:ss,fff") + "</td></tr><tr>");
                UpdateXML(Service, Environment, WGS, rows, dt);
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public void UpdateXML(String Service, String Environment, String WGS, List<String[]> rows, DataTable dt)
        {
            try
            {
                //Update CM XML File with Last Updated Date.
                if (Service != "" && Environment != "" && WGS != "")
                {
                    XDocument xmlDoc = XDocument.Load("CM_Monitor.xml");
                    var target = xmlDoc.Elements("Root").Elements("CM_Monitor").Elements("Environments").Elements("Environment").Where(e => e.Attribute("name").Value == Environment).Elements("WorkgroupServers").Elements("Workgroup").Where(e => e.Attribute("name").Value == WGS).Elements("LogPaths").Elements("Path").Where(e => e.Attribute("name").Value == Service).Single();
                    target.Attribute("lastupdated").Value = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss,fff");
                    xmlDoc.Save("CM_Monitor.xml");
                }
                //Create Detailed Log File.
                String csvFilePath = "Logs\\Detaliedlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv";
                using (StreamWriter writer = new StreamWriter(csvFilePath, true))
                {
                    if (new FileInfo(csvFilePath).Length == 0)
                    {
                        writer.WriteLine("Timestamp,Environment,WorkGroup Server,Dataset,Thread Id,Log Level,Error Message");
                    }
                    foreach (var row in rows)
                    {
                        writer.WriteLine(String.Join(",", row));
                    }
                }
                //Create Error Count Log File
                String filepath = "Logs\\Errorlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv";
                StringBuilder csvContent = new StringBuilder();
                if (!File.Exists(filepath))
                {
                    csvContent.AppendLine(String.Join(",", dt.Columns.Cast<DataColumn>().Select(col => col.ColumnName)));
                }
                foreach (DataRow row in dt.Rows)
                {
                    csvContent.AppendLine(String.Join(",", row.ItemArray.Select(field => QuoteIfNeeded(field + ""))));
                }
                File.AppendAllText(filepath, csvContent + "");
                log.Info("CSV Conversion Completed.");
            }
            catch (Exception ex)
            {
                log.Error(ex);
            }
        }

        static public String QuoteIfNeeded(String value)
        {
            if (value.Contains(",") || value.Contains("\"") || value.Contains("\r") || value.Contains("\n"))
            {
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            }
            else
            {
                return value;
            }
        }

        static public void SendMail(String From, String To, String Subject, String SmtpServer, int SmtpPort)
        {
            try
            {
                MailMessage mail = new MailMessage();
                mail.From = new MailAddress(From);
                mail.To.Add(To);
                mail.Subject = Subject;
                mail.IsBodyHtml = true;
                mail.Body = msgBuilder.ToString();
                mail.Attachments.Add(new Attachment("Logs\\Errorlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv"));
                mail.Attachments.Add(new Attachment("Logs\\Detaliedlog-" + DateTime.Now.ToString("ddMMyyyy") + ".csv"));
                SmtpClient smtpClient = new SmtpClient(SmtpServer, SmtpPort);
                smtpClient.EnableSsl = false;
                smtpClient.Send(mail);
            }
            catch (Exception ex)
            {
                log.Error(ex.Message);
            }
        }

        static public void DeleteLogFiles()
        {
            String[] files = Directory.GetFiles("Logs\\");
            foreach (String file in files)
            {
                try
                {
                    TimeSpan age = DateTime.Now - File.GetCreationTime(file);
                    if (age.TotalDays > 30)
                    {
                        File.Delete(file);
                        log.Info($"Deleted: " + file);
                    }
                }
                catch (Exception ex)
                {
                    log.Error($"Error deleting file " + file + ": " + ex);
                }
            }
        }
    }
}