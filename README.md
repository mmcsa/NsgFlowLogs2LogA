# NsgFlowLogFunctions
function apps for NSG flow log monitoring

This C# solution is intended to be deployed as a single Azure Function app. There are 3 sub-functions in the app which do the following:

1> ('Stage1BlobTrigger') monitor a designated blob storage account for block updates to NSG flow log files. A 10k change in blob size will trigger the function, which will pull the new blocks, validate data, and write the new block to a storage queue

2> ('Stage2QueueTrigger') monitors the queue used for stage 1 output, when a new message comes in it will trigger 2nd stage to parse an individual NSG flow log record (which may contain multiple flow tuples). The parsed record is then written out to a separate output storage queue.

3> ('Stage3QueueTrigger') triggered by new message output by stage 2, this will parse the individual flow tuples into a flat JSON message & POST to the Log Analytics HTTP Collector API as a new log of type = "NikeNsgFlowLogs_CL". 

required app settings - should be configured in 'Application Settings' of the Function App Service
- NSG log storage connection string name
- NSG log storage connection string (actual string ref'd by above)
- NSG log container (always 'insights-logs-networksecuritygroupflowevent')
- Log Analytics Workspace ID
- Log Analytics Workspace key
- 'Output Binding' currently only 'LogAnalytics', but this sets a switch to enable other future targets (Splunk)




