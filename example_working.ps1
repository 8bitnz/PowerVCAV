$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("X-VCAV-Auth", 'A1UBrcew17HWC0Fzh1mrU1Hl/eo=')
$headers.Add("Accept", 'application/vnd.vmware.h4-v3+json;charset=UTF-8')

$splat = @{
sourcetype = 'vapp'
sourcesite = 'CCL-North-Island'
sourcevappid = '098d434f-a662-46f7-a9c1-850ff24ed158'
sourcevappname = 'CCLENG_AK4_REPLICATION_TEST (1)'
destinationtype = 'vcloud'
destinationsite = 'CCL-South-Island'
destinationvdc = '9def03c1-e3a6-47e2-86c8-78bb25b8d1ed'
destinationvdcname = 'NN0 CCLENG Dedicated Allocated'
destinationstorageprofile = '80854c33-6caa-4c71-9ff1-45c4a0868d2a'
destinationstorageProfilename = 'NN0 CCL01 Performance 7969A'
}

$body = '{
    "source" : {
      "type" : "vapp",
      "site" : "CCL-North-Island",
      "vappId" : "098d434f-a662-46f7-a9c1-850ff24ed158"
    },
    "destination" : {
      "type" : "vcloud",
      "site" : "CCL-South-Island",
      "vdc" : "9def03c1-e3a6-47e2-86c8-78bb25b8d1ed",
      "storageProfile" : "80854c33-6caa-4c71-9ff1-45c4a0868d2a"
    },
    "description" : "A Protected Workload",
    "rpo" : 480,
    "dataConnectionType" : "ENCRYPTED",
    "quiesced" : true,
    "retentionPolicy" : {
      "rules" : [ {
        "numberOfInstances" : 3,
        "distance" : 60
      } ]
    },
    "targetDiskType" : "THIN",
    "initialSyncTime" : 0,
    "isMigration" : false
  }'

$splat 

$uri = 'https://chcav.cloud.concepts.co.nz/vapp-replications'

invoke-restmethod -URI $uri -Headers $headers -Body $body -Method 'POST' -ContentType 'application/json'




