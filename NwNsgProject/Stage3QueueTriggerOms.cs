using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Host;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Net.Sockets;
using Newtonsoft.Json;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;

namespace NwNsgProject
{
    public static class Stage3QueueTriggerOms
    {
        [FunctionName("Stage3QueueTrigger")]
        public static async Task Run(
            [QueueTrigger("stage2", Connection = "AzureWebJobsStorage")]Chunk inputChunk,
            Binder binder,
            Binder cefLogBinder,
            Binder errorRecordBinder,
            TraceWriter log)
        {
            //            log.Info($"C# Queue trigger function processed: {inputChunk}");

            string nsgSourceDataAccount = Util.GetEnvironmentVariable("nsgSourceDataAccount");
            if (nsgSourceDataAccount.Length == 0)
            {
                log.Error("Value for nsgSourceDataAccount is required.");
                throw new ArgumentNullException("nsgSourceDataAccount", "Please supply in this setting the name of the connection string from which NSG logs should be read.");
            }

            var attributes = new Attribute[]
            {
                new BlobAttribute(inputChunk.BlobName),
                new StorageAccountAttribute(nsgSourceDataAccount)
            };

            string nsgMessagesString;
            try
            {
                byte[] nsgMessages = new byte[inputChunk.Length];
                CloudBlockBlob blob = await binder.BindAsync<CloudBlockBlob>(attributes);
                await blob.DownloadRangeToByteArrayAsync(nsgMessages, 0, inputChunk.Start, inputChunk.Length);
                nsgMessagesString = System.Text.Encoding.UTF8.GetString(nsgMessages);
            }
            catch (Exception ex)
            {
                log.Error(string.Format("Error binding blob input: {0}", ex.Message));
                throw ex;
            }

            // skip past the leading comma
            string trimmedMessages = nsgMessagesString.Trim();
            int curlyBrace = trimmedMessages.IndexOf('{');
            string newClientContent = "{\"records\":[";
            newClientContent += trimmedMessages.Substring(curlyBrace);
            newClientContent += "]}";

            await SendMessagesDownstream(newClientContent, log);

            string logOutgoingCEF = Util.GetEnvironmentVariable("logOutgoingCEF");
            Boolean flag;
            if (Boolean.TryParse(logOutgoingCEF, out flag))
            {
                if (flag)
                {
                    await CEFLog(newClientContent, cefLogBinder, errorRecordBinder, log);
                }
            }
        }

        public static async Task SendMessagesDownstream(string myMessages, TraceWriter log)
        {
            string outputBinding = Util.GetEnvironmentVariable("outputBinding");
            if (outputBinding.Length == 0)
            {
                log.Error("Value for outputBinding is required. Permitted values are: 'LogAnalytics', 'arcsight'.");
                return;
            }

            switch (outputBinding)
            {
                case "LogAnalytics":
                    await obLogAnalytics(myMessages, log);
                    break;
                case "arcsight":
                    await obArcsight(myMessages, log);
                    break;
            }
        }

        static async Task CEFLog(string newClientContent, Binder cefLogBinder, Binder errorRecordBinder, TraceWriter log)
        {
            int count = 0;
            Byte[] transmission = new Byte[] { };

            foreach (var message in convertToCEF(newClientContent, errorRecordBinder, log))
            {

                try
                {
                    transmission = AppendToTransmission(transmission, message);

                    // batch up the messages
                    if (count++ == 1000)
                    {
                        Guid guid = Guid.NewGuid();
                        var attributes = new Attribute[]
                        {
                            new BlobAttribute(String.Format("ceflog/{0}", guid)),
                            new StorageAccountAttribute("cefLogAccount")
                        };

                        CloudBlockBlob blob = await cefLogBinder.BindAsync<CloudBlockBlob>(attributes);
                        await blob.UploadFromByteArrayAsync(transmission, 0, transmission.Length);

                        count = 0;
                        transmission = new Byte[] { };
                    }
                }
                catch (Exception ex)
                {
                    log.Error($"Exception logging CEF output: {ex.Message}");
                }
            }

            if (count != 0)
            {
                Guid guid = Guid.NewGuid();
                var attributes = new Attribute[]
                {
                    new BlobAttribute(String.Format("ceflog/{0}", guid)),
                    new StorageAccountAttribute("cefLogAccount")
                };

                CloudBlockBlob blob = await cefLogBinder.BindAsync<CloudBlockBlob>(attributes);
                await blob.UploadFromByteArrayAsync(transmission, 0, transmission.Length);
            }
        }

        static System.Collections.Generic.IEnumerable<string> convertToCEF(string newClientContent, Binder errorRecordBinder, TraceWriter log)
        {
            // newClientContent is a json string with records

            NSGFlowLogRecords logs = JsonConvert.DeserializeObject<NSGFlowLogRecords>(newClientContent);

            string logIncomingJSON = Util.GetEnvironmentVariable("logIncomingJSON");
            Boolean flag;
            if (Boolean.TryParse(logIncomingJSON, out flag))
            {
                if (flag)
                {
                    logErrorRecord(newClientContent, errorRecordBinder, log).Wait();
                }
            }

            string cefRecordBase = "";
            foreach (var record in logs.records)
            {
                cefRecordBase =  "{\"time\":\"" + record.MakeCEFTime() + "\",";
                cefRecordBase += "\"provider\":\"Microsoft.Network\",";
                cefRecordBase += "\"resourceType\":\"NETWORKSECURITYGROUPS\",";
                cefRecordBase += "\"recordCategory\":\"" + record.category + "\",";
                cefRecordBase += "\"operationName\":\"" + record.operationName + "\",";
                cefRecordBase += "\"resourceId\":\"" + record.MakeDeviceExternalID() + "\",";

                int count = 1;
                foreach (var outerFlows in record.properties.flows)
                {
                    string cefOuterFlowRecord = cefRecordBase;
                    cefOuterFlowRecord += String.Format("\"cs{0}\":\"", count) + outerFlows.rule + "\",";
                    cefOuterFlowRecord += String.Format("\"cs{0}Label\":\"NSGRuleName\",", count++);

                    foreach (var innerFlows in outerFlows.flows)
                    {
                        var cefInnerFlowRecord = cefOuterFlowRecord;

                        var firstFlowTupleEncountered = true;
                        foreach (var flowTuple in innerFlows.flowTuples)
                        {
                            var tuple = new NSGFlowLogTuple(flowTuple);

                            if (firstFlowTupleEncountered)
                            {
                                cefInnerFlowRecord += (tuple.GetDirection == "I" ? "\"dmac\":\"" : "\"smac\":\"") + innerFlows.MakeMAC() + "\",";
                                firstFlowTupleEncountered = false;
                            }

                            yield return cefInnerFlowRecord + " " + tuple.ToString();
                        }
                    }
                }
            }
        }

        static async Task logErrorRecord(NSGFlowLogRecord errorRecord, Binder errorRecordBinder, TraceWriter log)
        {
            if (errorRecordBinder == null) { return; }

            Byte[] transmission = new Byte[] { };

            try
            {
                transmission = AppendToTransmission(transmission, errorRecord.ToString());

                Guid guid = Guid.NewGuid();
                var attributes = new Attribute[]
                {
                    new BlobAttribute(String.Format("errorrecord/{0}", guid)),
                    new StorageAccountAttribute("cefLogAccount")
                };

                CloudBlockBlob blob = await errorRecordBinder.BindAsync<CloudBlockBlob>(attributes);
                blob.UploadFromByteArray(transmission, 0, transmission.Length);

                transmission = new Byte[] { };
            }
            catch (Exception ex)
            {
                log.Error($"Exception logging record: {ex.Message}");
            }
        }

        static async Task logErrorRecord(string errorRecord, Binder errorRecordBinder, TraceWriter log)
        {
            if (errorRecordBinder == null) { return; }

            Byte[] transmission = new Byte[] { };

            try
            {
                transmission = AppendToTransmission(transmission, errorRecord);

                Guid guid = Guid.NewGuid();
                var attributes = new Attribute[]
                {
                    new BlobAttribute(String.Format("errorrecord/{0}", guid)),
                    new StorageAccountAttribute("cefLogAccount")
                };

                CloudBlockBlob blob = await errorRecordBinder.BindAsync<CloudBlockBlob>(attributes);
                blob.UploadFromByteArray(transmission, 0, transmission.Length);

                transmission = new Byte[] { };
            }
            catch (Exception ex)
            {
                log.Error($"Exception logging record: {ex.Message}");
            }
        }
        static async Task obArcsight(string newClientContent, TraceWriter log)
        {
            string arcsightAddress = Util.GetEnvironmentVariable("arcsightAddress");
            string arcsightPort = Util.GetEnvironmentVariable("arcsightPort");

            if (arcsightAddress.Length == 0 || arcsightPort.Length == 0)
            {
                log.Error("Values for arcsightAddress and arcsightPort are required.");
                return;
            }

            TcpClient client = new TcpClient(arcsightAddress, Convert.ToInt32(arcsightPort));
            NetworkStream stream = client.GetStream();

            int count = 0;
            Byte[] transmission = new Byte[] { };
            foreach (var message in convertToCEF(newClientContent, null, log))
            {

                try
                {
                    transmission = AppendToTransmission(transmission, message);

                    // batch up the messages
                    if (count++ == 1000)
                    {
                        await stream.WriteAsync(transmission, 0, transmission.Length);
                        count = 0;
                        transmission = new Byte[] { };
                    }
                }
                catch (Exception ex)
                {
                    log.Error($"Exception sending to ArcSight: {ex.Message}");
                }
            }
            if (count > 0)
            {
                try
                {
                    await stream.WriteAsync(transmission, 0, transmission.Length);
                }
                catch (Exception ex)
                {
                    log.Error($"Exception sending to ArcSight: {ex.Message}");
                }
            }
            await stream.FlushAsync();
        }

        static Byte[] AppendToTransmission(Byte[] existingMessages, string appendMessage)
        {
            Byte[] appendMessageBytes = Encoding.ASCII.GetBytes(appendMessage);
            Byte[] crlf = new Byte[] { 0x0D, 0x0A };

            Byte[] newMessages = new Byte[existingMessages.Length + appendMessage.Length + 2];

            existingMessages.CopyTo(newMessages, 0);
            appendMessageBytes.CopyTo(newMessages, existingMessages.Length);
            crlf.CopyTo(newMessages, existingMessages.Length + appendMessageBytes.Length);

            return newMessages;
        }

        //public class SingleHttpClientInstance
        //{
        //    private static readonly HttpClient HttpClient;

        //    static SingleHttpClientInstance()
        //    {
        //        HttpClient = new HttpClient();
        //        HttpClient.Timeout = new TimeSpan(0, 1, 0);
        //    }

        //    public static async Task<HttpResponseMessage> SendToLogAnalytics(HttpRequestMessage req, TraceWriter log)
        //    {
        //        HttpResponseMessage response = null;
        //        var httpClient = new HttpClient();
        //        httpClient.Timeout = TimeSpan.FromMinutes(5);
        //        try
        //        {
        //            response = await httpClient.SendAsync(req);
        //        }
        //        catch (AggregateException ex)
        //        {
        //            log.Error("Got AggregateException.");
        //            throw ex;
        //        }
        //        catch (TaskCanceledException ex)
        //        {
        //            log.Error("Got TaskCanceledException.");
        //            throw ex;
        //        }
        //        catch (Exception ex)
        //        {
        //            log.Error("Got other exception.");
        //            throw ex;
        //        }
        //        return response;
        //    }
        //}

        static async Task obLogAnalytics(string newClientContent, TraceWriter log)
        {
            string loganalyticsWorkspaceId = Util.GetEnvironmentVariable("logAnalyticsWorkspaceId");
            string loganalyticsWorkspaceKey = Util.GetEnvironmentVariable("logAnalyticsWorkspaceKey");
            string loganalyticsAddress = "https://" + loganalyticsWorkspaceId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";
            string LogName = "NikeNsgFlowLogs_CL";
            string TimeStampField = "";

            if (loganalyticsAddress.Length == 0 || loganalyticsWorkspaceId.Length == 0 || loganalyticsWorkspaceKey.Length == 0)
            {
                log.Error("Values for loganalyticsAddress, logstashWorkspaceId and loganalyticsWorkspaceKey are required.");
                return;
            }
            foreach (var message in convertToCEF(newClientContent, null, log))
            {
                    // Create a hash for the API signature
                    var datestring = DateTime.UtcNow.ToString("r");
                var jsonBytes = Encoding.UTF8.GetBytes(message);
                string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
                string hashedString = BuildSignature(stringToHash, loganalyticsWorkspaceKey);
                string signature = "SharedKey " + loganalyticsWorkspaceId + ":" + hashedString;

                string BuildSignature(string content, string secret)
                {
                    var encoding = new System.Text.ASCIIEncoding();
                    byte[] keyByte = Convert.FromBase64String(secret);
                    byte[] messageBytes = encoding.GetBytes(content);
                    using (var hmacsha256 = new HMACSHA256(keyByte))
                    {
                        byte[] hash = hmacsha256.ComputeHash(messageBytes);
                        return Convert.ToBase64String(hash);
                    }
                }
                try
                {
                    System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
                    client.DefaultRequestHeaders.Add("Accept", "application/json");
                    client.DefaultRequestHeaders.Add("Log-Type", LogName);
                    client.DefaultRequestHeaders.Add("Authorization", signature);
                    client.DefaultRequestHeaders.Add("x-ms-date", datestring);
                    client.DefaultRequestHeaders.Add("time-generated-field", TimeStampField);

                    System.Net.Http.HttpContent httpContent = new StringContent(message, Encoding.UTF8);
                    httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                    Task<System.Net.Http.HttpResponseMessage> response = client.PostAsync(new Uri(loganalyticsAddress), httpContent);
                }
                catch (System.Net.Http.HttpRequestException e)
                {
                    string msg = e.Message;
                    if (e.InnerException != null)
                    {
                        msg += " *** " + e.InnerException.Message;
                    }
                    log.Error($"HttpRequestException Error: \"{msg}\" was caught while sending to LogAnalytics.");
                    throw e;
                }
                catch (Exception f)
                {
                    string msg = f.Message;
                    if (f.InnerException != null)
                    {
                        msg += " *** " + f.InnerException.Message;
                    }
                    log.Error($"Unknown error caught while sending to LogAnalytics: \"{f.ToString()}\"");
                    throw f;
                }

            
            }
        }
    }
}