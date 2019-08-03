# PowerVCAV.psm1
#
# PS Module to more easily interrogate the vCloud Availability 3.0 API
#
# Requires that you are already connected to the appropriate vCloud Director
# site(s) - powervcav will use the $Global:DefaultCIServers context to extract
# vCD session keys and use these to authenticate to vCAv. VMware PowerCLI is
# required for this module to function.
#
# Copyright 2019 Jon Waite, All Rights Reserved
# Released under MIT License - see https://opensource.org/licenses/MIT
# Date:         1st June 2019
# Version:      0.2.2
#
# Updated Alex Smith 
# Date:         24th June 2019
# Version:      0.3.0
# Change:       Adding functions for managing replicaitons

Function Connect-VCAV {
<#
.SYNOPSIS
Connect-VCAV makes a connection to the vCloud Availability (VCAV) 3.0 API
.DESCRIPTION
Connect-VCAV uses the session secret of an existing vCloud Director
connection (obtained from Connect-CIServer). If more that one vCloud Director
connection exists both the VCAV host and VCD host must be specified. The VCAV
session is persisted in session variables for use by other commands in this
module (e.g. Invoke-VCAVQuery).
.PARAMETER VCAVHost
A required parameter containing the API endpoint for the vCloud Availability
service, typically this will be the public URI for the VCAV service.
.PARAMETER VCDHost
The API endpoint for vCloud Director, typically this will be the public URI for
the vCloud Director instance. This parameter is required if multiple vCD API
endpoints are currently connected, otherwise it is optional.
.OUTPUTS
A status message (success or failure) is given for the connection attempt.
.EXAMPLE
Connect-VCAV -VCAVHost 'myvcav.cloud.com' -VCDHost 'myvcd.cloud.com'
.NOTES
If more than one vCD environment is currently connected (Connect-CIServer), the
host name specified for the VCDHost must match the name used when the original
Connect-CIServer command was issued so that the correct session can be located
in the $Global:DefaultCIServers array.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VCAVHost,
        [Parameter()][string]$VCDHost
    )
     
    # Check if we are already connected to this VCAVHost:
    if ($Script:VCAVIsConnected -eq $true) {
        Write-Error ("Already connected to VCAV, logout before attempting to login again")
        return
    }

    $vCDCount = $Global:DefaultCIServers.Count

    # Not connected to any vCD instances, can't continue:
    if ($vCDCount -eq 0) {
        Write-Error ("Not currently connected to any vCloud Director cells, cannot attach to vCloud Availability - Use Connect-CIServer first")
        return
    }

    if ($vCDCount -gt 1) {
        # We are connected to multiple vCD environments, match the supplied $VCDHost in the global array:
        $vCDSecret = ($Global:DefaultCIServers | Where-Object { $_.Name -eq $VCDHost }).SessionSecret
        if (!$vCDSecret) {
            Write-Error ("Cannot find a connection to vCloud Director that matches host $VCDHost, connect first using Connect-CIServer with this hostname")
            return
        } 
    }
    else {
        # There is only 1 connection so just use the session secret from that: 
        $vCDSecret = $Global:DefaultCIServers.SessionSecret
    }

    # Attempt to establish initial/primary connection to the vCAV API:
    $AuthBody = [PSCustomObject]@{
        type      = "vcdCookie"
        vcdCookie = $vcdSecret
    } | ConvertTo-Json -Compress

    try {
        $PriVCAV = Invoke-WebRequest -Uri "https://$VCAVHost/sessions" -Method Post -ContentType 'application/json' -Body $AuthBody
    }
    catch {
        Write-Error ("Could not connect to vCloud Availability, error message: " + $_.Exception.Message)
        $Script:VCAVIsConnected = $false
        Break
    }
    
    $Script:VCAVHost = $VCAVHost
    $Script:VCAVIsConnected = $true
    if ($PriVCAV.Headers.'X-VCAV-Auth' -is [Array]) {
        $Script:VCAVToken = $PriVCAV.Headers.'X-VCAV-Auth'[0]
    } else {
        $Script:VCAVToken = $PriVCAV.Headers.'X-VCAV-Auth'
    }
    $Script:VCDPriHost = $VCDHost
    Write-Host -ForegroundColor Green ("Logged in to VCAV successfully")
    return
}

Function Disconnect-VCAV {
<#
.SYNOPSIS
Disconnect-VCAV logs out from the vCloud Availability (VCAV) 3.0 API
.DESCRIPTION
Disconnect-VCAV clears any sessions from the vCloud Availability API including
any extended sites
.OUTPUTS
A status message (success or failure) is given for the disconnection attempt.
.EXAMPLE
Disconnect-VCAV
.NOTES
If a vCloud Availability API session has timed-out due to inactivity the
Disconnect-VCAV command will clear out the stale session variables so that
Connect-VCAV can be re-used to establish a new session.
#>
    [CmdletBinding()]
    param ()

    if (!$Script:VCAVHost) {
        Write-Error ("Can't find session, exiting.")
        exit
    }
    $Uri = "https://$Script:VCAVHost/sessions"
    $VCAHeader = @{'X-VCAV-Auth' = $($VCAVToken) }
    
    # Clear session state variables:
    if ($Script:VCAVHost) { Remove-Variable -Scope Script -Name VCAVHost -Confirm:$false }
    if ($Script:VCAVToken) { Remove-Variable -Scope Script -Name VCAVToken -Confirm:$false }
    if ($Script:VCAVIsConnected) { Remove-Variable -Scope Script -Name VCAVIsConnected -Confirm:$false }
    if ($Script:VCDPriHost) { Remove-Variable -Scope Script -Name VCDPriHost -Confirm:$false }
    
    Try {
        Invoke-WebRequest -Uri $Uri -Method Delete -Headers $VCAHeader -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-Error ("ERROR: " + $_.Exception.Message)
        Break
    }
    Write-Host -ForegroundColor Green "Logged out successfully."
}

Function Connect-VCAVExtend {
<#
.SYNOPSIS
Connect-VCAVExtend extends the current vCloud Availability session to
additional VCAV sites.
.DESCRIPTION
Connect-VCAVExtend uses the session secret of an existing vCloud Director
connections (obtained from Connect-CIServer) to extend the VCAV session to
additional sites. The VCAV Site Name and VCD host to be extended to must
be specified. The extended session is persisted in session variables for use
by other commands in this module (e.g. Invoke-VCAVQuery).
.PARAMETER VCAVHost
A required parameter containing the VCAV Site Name (e.g. 'My-2nd-Site') which
matches the vCloud Director endpoint specified in -VCDHost.
.PARAMETER VCDHost
A required parameter containing The API endpoint for vCloud Director at the
site to be extended to, typically this will be the public URI for the vCloud
Director instance.
.OUTPUTS
A status message (success or failure) is given for the connection extension
attempt.
.EXAMPLE
Connect-VCAVExtend -VCAVSiteName 'Site2' -VCDHost 'vcdsite2.cloud.com'
.NOTES
The host name specified for the VCDHost must match the name used when the
original Connect-CIServer command was issued so that the correct session can be
located in the $Global:DefaultCIServers array. A list of valid VCAV site names
can be obtained using the Invoke-VCAVQuery cmdlet with -QueryPath of 'sites'.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$VCAVSiteName,
        [Parameter(Mandatory = $true)][string]$VCDHost
    )
    if ($Script:VCAVIsConnected -ne $true) # Not authenticated to API
    { Write-Error ("VCAV not logged in, cannot extend to another site, use Connect-VCAV first."); return }

    $vCDSecret = ($Global:DefaultCIServers | Where-Object { $_.Name -eq $VCDHost }).SessionSecret
    if (!$vCDSecret) {
        Write-Error ("Cannot find a connection to vCloud Director that matches host $VCDHost, connect first using Connect-CIServer with this hostname.")
        return
    } 

    $AuthBody = [PSCustomObject]@{
        type   = "cookie"
        site   = $VCAVSiteName
        cookie = $vCDSecret
    } | ConvertTo-Json -Compress

    $VCAVHeader = @{'X-VCAV-Auth' = $Script:VCAVToken }

    Try {
        Invoke-WebRequest -Uri "https://$Script:VCAVHost/sessions/extend" -Method Post -Headers $VCAVHeader -Body $AuthBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
    }
    Catch {
        Write-Error ("ERROR: " + $_.Exception.Message)
        Break
    }
    Write-Host -ForegroundColor Green ("Extended session to " + $VCAVSite + " successfully.")
    return
}

Function Get-VCAVToken {
<#
.SYNOPSIS
Returns the vCloud Availability session token for the current session.
.DESCRIPTION
Get-VCAVToken returns a string containing the VCAV session token for the
currently connected VCAV session as used in the 'X-VCAV-Auth' token in
API requests.
.OUTPUTS
A string containing the VCAV token for the current VCAV session.
.EXAMPLE
Get-VCAVToken
.NOTES
If no session is currently connected an empty string will be returned.
#>
    [CmdletBinding()]
    param()
    return $Script:VCAVToken
}

Function Invoke-VCAVPagedQuery {
<#
.SYNOPSIS
Query the vCloud Availability (VCAV) API
.DESCRIPTION
Invoke-VCAVPagedQuery queries the vCloud Availability API for the specified 
resource which is returned as a PSCustomObject. Queries which return more than
100 objects are split into 100 object chunks so that all returned values are
obtained. Parameters can be specified to limit the returned results by a filter
(see Examples).
.PARAMETER QueryPath
A required parameter containing the API resource to retrieve.
.PARAMETER Headers
An optional parameter containing any additional HTML headers to pass to the API
note that the 'X-VCAV-Auth' token is populated automatically based on existing
sessions to the API and the 'Accept' token is automatically set to the value
'application/vnd.vmware.h4-v3+json;charset=UTF-8' if not specified. This is
appropriate for the majority of VCAV API queries.
.PARAMETER Filter
An optional parameter to restrict the results returned by encoding additional
filters in the query Uri. See https://code.vmware.com/apis/441/vcav for
details of the valid filter parameters for each method call.
.OUTPUTS
A PSCustomObject containing the resources from the API call or an error.
.EXAMPLE
Get a list of VCAV vApp Replications:
Invoke-VCAVPagedQuery -QueryPath 'vapp-replications'
.EXAMPLE
Retrieve a list of vApp replications for the vCD Organization 'myorg':
Invoke-VCAVPagedQuery -QueryPath 'vapp-replications' -Filter @{ sourceSite='myorg' }
.NOTES
The parameters used in the -Filter argument for each query type are specified
in the VCAV API documentation at https://code.vmware.com/apis/441/vcav
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$QueryPath,
        [Parameter()][hashtable]$Headers,
        [Parameter()][hashtable]$Filter
    )
    $offset = 0
    $limit = 100
    $items = @()
    if (!$Filter) { $Filter = @{} }
    While ($true) {
        $Uri = New-VCAVUrl -QueryPath $QueryPath -Filter (@{offset = $offset; limit = $limit } + $Filter)
        $result = Invoke-VCAVQuery -Uri $Uri -Method Get -Headers $Headers
        $items += ($result.items)
        $offset += $result.items.Count
        if ($offset -ge $result.total) { Break }
    }
    return $items
}

Function Invoke-VCAVQuery {
<#
.SYNOPSIS
Query the vCloud Availability (VCAV) API
.DESCRIPTION
Invoke-VCAVQuery queries the vCloud Availability API for the specified resource
which is returned as a PSCustomObject. Parameters can be specified to limit
the returned results by a filter (see Examples).
.PARAMETER Uri
An optional parameter containing the absolute URI to be queried, note that if
this parameter is used the -QueryPath and -Filter parameters are ignored.
.PARAMETER QueryPath
An optional parameter containing the API resource to retrieve.
.PARAMETER Method
An optional parameter containing the HTML method to use in the query
(default='Get' if not specified)
.PARAMETER Headers
An optional parameter containing any additional HTML headers to pass to the API
note that the 'X-VCAV-Auth' token is populated automatically based on existing
sessions to the API and the 'Accept' token is automatically set to the value
'application/vnd.vmware.h4-v3+json;charset=UTF-8' if not specified. This is
appropriate for the majority of VCAV API queries.
.PARAMETER Filter
An optional parameter to restrict the results returned by encoding additional
filters in the query Uri. See https://code.vmware.com/apis/441/vcav for
details of the valid filter parameters for each method call.
.PARAMETER ContentType
An optional parameter specifying the HTML ContentType of the submitted API
request, generally this should only be specified for requests which send data
to the API using the -Body parameter.
.PARAMETER Body
An optional parameter specifying the JSON document to be submitted to the VCAV
API, generally this will also require setting the -ContentType parameter.
.OUTPUTS
A PSCustomObject containing the resources from the API call or an error.
.EXAMPLE
Get a list of VCAV organizations:
Invoke-VCAVQuery -QueryPath 'inventory/orgs'
.EXAMPLE
Retrieve a list of VCAV sites:
Invoke-VCAVQuery -QueryPath 'sites'
.EXAMPLE
Retrieve the current connection details for this VCAV session:
Invoke-VCAVQuery -QueryPath 'sessions'
.NOTES
For queries which can return a large number of results (>100 typically) use
the Invoke-VCAVPagedQuery cmdlet to ensure that all results are retrieved.
#>
    [CmdletBinding()]
    param(
        [Parameter()][string]$Uri,
        [Parameter()][string]$QueryPath,
        [Parameter()][Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'Get',
        [Parameter()][hashtable]$Headers,
        [Parameter()][hashtable]$Filter,
        [Parameter()][string]$ContentType,
        [Parameter()][string]$Body
    )

    if ($Script:VCAVIsConnected -ne $true) # Not authenticated to API
    { Write-Error ("Not connected to VCAV API, authenticate first with Connect-VCAV"); Break }
    
    if (!$Uri) {
        $UriParams = @{ QueryPath = $QueryPath }
        if ($Filter) { $UriParams.Filter = $Filter }
        $Uri = New-VCAVUrl @UriParams
    }

    if (!$Headers) { $Headers = @{ } 
    }
    
    if (! ($Headers.ContainsKey('X-VCAV-Auth'))) {
        $Headers.Add('X-VCAV-Auth', $Script:VCAVToken)
    }

    if (! ($Headers.ContainsKey('Accept'))) {
        $Headers.Add('Accept', 'application/vnd.vmware.h4-v3+json;charset=UTF-8')
    }

    $InvokeParams = @{
        Uri     = $Uri
        Method  = $Method
        Headers = $Headers
    }
    if ($ContentType) { $InvokeParams.ContentType = $ContentType }
    if ($Body) { $InvokeParams.Body = $Body }
    Try {
        $result = Invoke-RestMethod @InvokeParams -ErrorAction Stop
        return $result
    }
    Catch {
        Write-Error ("vCloud Availability API error: $($_.Exception.Message)")
        Break
    }
}

# An internal function to convert the supplied parameters into a query URL to
# be submitted against the VCAV API
Function New-VCAVUrl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$QueryPath,
        [Parameter()][hashtable]$Filter
    )

    $QueryString = "https://$Script:VCAVHost/$QueryPath"

    if ($Filter) {
        $FirstParam = $true
        foreach ($key in $Filter.Keys) {
            $QueryString += if ($FirstParam) { "?" } Else { "&" }
            $FirstParam = $false
            $QueryString += "$key=$($Filter.Item($key))"
        }
    }
    return $QueryString
}

# Internal functions to Test function input
# 
Function Test-VCAVSiteName {
    [CmdletBinding()]
    param(
        [Parameter()][string]$SiteName
    )

    #Invoke-VCAVQuery -QueryPath 'sites'
    #/sites is an undocumented API endpoint
    $result = (Invoke-VCAVQuery -QueryPath 'sites') | Where-Object {$_.site -like $SiteName}
    if (!$result) 
    { Write-Error ( "Invalid Site Name : $SiteName"); return $false}
    
    return $true
}
        
# Test valid source vapp name
# Fails if more than one result is returned
# Returns the ID, which is required by the vCAV API
Function Test-VCAVvCDvApp {
    [CmdletBinding()]
    param(
        [Parameter()][string]$vAppName
    ) 

    $result = Get-CIvApp -Name $vAppName -ErrorAction SilentlyContinue

    if (!$result) { Write-Error ( "Invalid vApp Name : $vAppName" ); return $false }

    if ($result.count -ne 1){ Write-Error ( "vApp Name is not unique : $($result.name)" ); return $false }

    return $result.id.Substring(16)

}

# Test valid destination OrgVDC
# Returns the ID, which is required by the vCAV API
Function Test-VCAVDestOrgVDC {
    [CmdletBinding()]
    param(
        [Parameter()][string]$DestinationVdc
    )

    $result = Get-OrgVdc -Name $DestinationVdc -ErrorAction SilentlyContinue

    if ($result.name -ne $DestinationVdc) 
    { Write-Error ( "Invalid Organistation VDC : $DestinationVdc"); return $false }

    return ($result.Id.Substring(15))    

}

#Test valid destination OrgVDC Storage Policy
# Returns the ID, which is required by the vCAV API
Function Test-VCAVDestOrgVDCStoragePolicy {
    [CmdletBinding()]
    param(
        [Parameter()][string]$DestinationStorageProfile,
        [Parameter()][string]$DestinationVdcId
    )

    $result = Get-OrgVdc -Id "urn:vcloud:vdc:$DestinationVdcId" -ErrorAction SilentlyContinue

    if ($result.ExtensionData.VdcStorageProfiles.VdcStorageProfile.Name -notcontains $DestinationStorageProfile)
    { Write-Error ( "The Organsiation VDC does not contain a storage policy matching : $DestinationStorageProfile"); return $false }     

    return ($result.ExtensionData.VdcStorageProfiles.VdcStorageProfile | Where-Object Name -EQ $DestinationStorageProfile).id.Substring(29)  
}



function Suspend-VCAVReplication {
    <#
    .SYNOPSIS
    Pauses an existing replication via the vCloud Availability (VCAV) API
    .DESCRIPTION
    Pause-VCAVReplication pauses an existing VM or vApp replication, returning a task object.
    (see Examples).
    .PARAMETER SourcevAppName
    The name of the vapp
    .OUTPUTS
    A PSCustomObject containing the task ID from the API call or an error.
    .EXAMPLE
    Pause a vApp replication betwen vCloud Director sites
    Suspend-VCAVReplication -SourcevAppName 'vApp' 
    .NOTES

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$sourcevappname
    )
    
    begin {
        if ($PSCmdlet.SessionState.PSVariable.GetValue('VCAVIsConnected') -ne $true) # Not authenticated to API
        { Write-Error ("Not connected to VCAV API, authenticate first with Connect-VCAV"); Break }
        
        #Confirm vApp is replicated, grab replicaitonID
        $sourcerepid = (Invoke-VCAVQuery -QueryPath 'vapp-replications' -Filter @{vappName='$sourcevappname'}).items.vmReplications.ID

        if (($sourcerepid) -eq $false) 
        { Write-Error ("Invalid vApp Name $sourcevappname"); Break }
   
        $UriParams = @{
            QueryPath = "/vapp-replications/$sourcerepid/pause"
        }
    
        $uri = New-VCAVUrl @UriParams
    
        $Headers = @{ } 
        $Token = Get-VCAVToken
    
        if ($Token -is [array]) { $Token = $Token[0] }
        $Headers.Add('X-VCAV-Auth', $Token)
        $Headers.Add('Accept', 'application/vnd.vmware.h4-v3+json;charset=UTF-8')
 
        $InvokeParams = @{
            Method    = 'POST'
            Uri       = $uri  
            Headers   = $Headers
            ContentType = 'application/json'
        }

        Write-Verbose ("Calling API with parameters : $InvokeParams")
    }

    process {
        Try {
            $result = Invoke-RestMethod @InvokeParams -ErrorAction Stop
            return $result
        }
        Catch {
            Write-Error ("vCloud Availability API error: $($_.Exception.Message)")
            Write-Verbose "$_"
            }
            Break
                    
    }
    
    end {
    }
}

function Resume-VCAVReplication {
    <#
    .SYNOPSIS
    Resumes a paused replication via the vCloud Availability (VCAV) API
    .DESCRIPTION
    Resume-VCAVReplication resumes an existing VM or vApp replication, returning a task object.
    (see Examples).
    .PARAMETER SourcevAppName
    The name of the vapp
    .OUTPUTS
    A PSCustomObject containing the task ID from the API call or an error.
    .EXAMPLE
    Resumes a vApp replication betwen vCloud Director sites
    Resume-VCAVReplication -SourcevAppName 'vApp' 
    .NOTES

    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$sourcevappname
    )
    
    begin {
        if ($PSCmdlet.SessionState.PSVariable.GetValue('VCAVIsConnected') -ne $true) # Not authenticated to API
        { Write-Error ("Not connected to VCAV API, authenticate first with Connect-VCAV"); Break }
        
        #Confirm vApp is replicated, grab replicaitonID
        $sourcerepid = (Invoke-VCAVQuery -QueryPath 'vapp-replications' -Filter @{vappName='$sourcevappname'}).items.vmReplications.ID

        if (($sourcerepid) -eq $false) 
        { Write-Error ("Invalid vApp Name $sourcevappname"); Break }
   
        $UriParams = @{
            QueryPath = "/vapp-replications/$sourcerepid/resume"
        }
    
        $uri = New-VCAVUrl @UriParams
    
        $Headers = @{ } 
        $Token = Get-VCAVToken
    
        if ($Token -is [array]) { $Token = $Token[0] }
        $Headers.Add('X-VCAV-Auth', $Token)
        $Headers.Add('Accept', 'application/vnd.vmware.h4-v3+json;charset=UTF-8')
 
        $InvokeParams = @{
            Method    = 'POST'
            Uri       = $uri  
            Headers   = $Headers
            ContentType = 'application/json'
        }

        Write-Verbose ("Calling API with parameters : $InvokeParams")
    }

    process {
        Try {
            $result = Invoke-RestMethod @InvokeParams -ErrorAction Stop
            return $result
        }
        Catch {
            Write-Error ("vCloud Availability API error: $($_.Exception.Message)")
            Write-Verbose "$_"
            }
            Break
                    
    }
    
    end {
    }
}

function x-VCAVReplication {
    <#
    .SYNOPSIS
     an existing replication via the vCloud Availability (VCAV) API
    .DESCRIPTION
    Disable-VCAVReplication removes and existing VM or vApp replication, returning a task object.
    (see Examples).
    .PARAMETER SourcevAppName
    The name of the vapp
    .OUTPUTS
    A PSCustomObject containing the task ID from the API call or an error.
    .EXAMPLE
    Disable a vApp replication betwen vCloud Director sites
    Disable-VCAVReplication -SourcevAppName 'vApp' 
    .NOTES
    Currently not implemented.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$sourcevappname
    )
    
    begin {
    }
    
    process {
        Write-Output "Not yet implemented"
    }
    
    end {
    }
}

Function Enable-VCAVReplication {
    <#
    .SYNOPSIS
    Configure a new replication via the vCloud Availability (VCAV) API
    .DESCRIPTION
    Enable-VCAVReplication configures a new VM or vApp replication, returning the replication 
    as a PSCustomObject. Currently only supports vCloud Director
    site to site replication and only VM replications (see Examples).
    .PARAMETER SourceType
    One of 'vcvm','vm','vapp'
    .PARAMETER SourceSiteName
    The name of the source site
    .PARAMETER SourcevAppName
    The name of the vapp
    .PARAMETER DestinationType
    One of 'vc','vcloud','vm','vapp'
    .PARAMETER DestinationSiteName
    The name of the destination site
    .PARAMETER DestinationVDCName
    The name of the Destination VDC
    .PARAMETER DestinationStorageProfileName
    The name of the Destination Storage Profile
    .OUTPUTS
    A PSCustomObject containing the resources from the API call or an error.
    .EXAMPLE
    Create a new vApp replication betwen vCloud Director sites
    Enable-VCAVReplication -SourceType 'vApp' -SourceSite 'site1' -SourcevAppName 'MyvApp'
    -DestinationType 'vCloud' -DestinationSite 'site2' - DestinationVDC 'My Org VDC' 
    -DestinationStorageProfile 'My Storage Profile'
    .NOTES
    
    #>
        [CmdletBinding(SupportsShouldProcess=$False)]
        param(
            [Parameter(Mandatory=$true)][ValidateSet('vcvm','vm','vapp')][string]$sourcetype,
            [Parameter(Mandatory=$true)][string]$sourcesite,
            [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$sourcevappname,
            [Parameter(Mandatory=$true)][ValidateSet('vc','vcloud','vm','vapp')][string]$destinationtype,
            [Parameter(Mandatory=$true)][string]$destinationsite,
            [Parameter(Mandatory=$true)][string]$destinationvdcname,
            [Parameter(Mandatory=$true)][string]$destinationstorageProfilename,
            [Parameter()][string]$description = '',
            [Parameter()][int32]$rpo = 1440,
            [Parameter()][ValidateSet('plain','encrypted','encrypted_compressed')][string]$dataConnectionType = 'plain',
            [Parameter()][bool]$quiesced = $false,
            [Parameter()][int32]$retentionPolicynumberOfInstances = 1,
            [Parameter()][int32]$retentionPolicydistance = 60,
            [Parameter()][ValidateSet('thin', 'preallocated', 'preallocated_zeros')][string]$targetDiskType = 'preallocated_zeros',
            [Parameter()][datetime]$initialSyncTime = '1970-01-01T00:00:00',
            [Parameter()][bool]$isMigration = $false
        )
    
        begin {
            if ($PSCmdlet.SessionState.PSVariable.GetValue('VCAVIsConnected') -ne $true) # Not authenticated to API
            { Write-Error ("Not connected to VCAV API, authenticate first with Connect-VCAV"); Break }
            
            #Test valid site name, could be more efficient 
            $result = Test-VCAVSiteName -SiteName $sourcesite
            if (( $result) -eq $false) 
            { Write-Error ("Invalid Site Name $sourcesite"); Break }

            $result = Test-VCAVSiteName -SiteName $destinationsite
            if (($result) -eq $false) 
            { Write-Error ("Invalid Site Name $destinationsite"); Break }
            
            #Test valid source vapp name
            $sourcevappid = Test-VCAVvCDvApp -vAppName $sourcevappname
            if (($sourcevappid) -eq $false) 
            { Write-Error ("Invalid vApp Name $sourcevappname"); Break }
            
            #Test valid destination OrgVDC
            $destinationvdc = Test-VCAVDestOrgVDC -DestinationVdc $destinationvdcname
            if (($destinationvdc) -eq $false) 
            { Write-Error ("Invalid Organisation VDC Name $destinationvdcname"); Break }
            
            #Test valid destination OrgVDC Storage Policy
            $destinationstorageProfile = Test-VCAVDestOrgVDCStoragePolicy -DestinationStorageProfile $destinationstorageProfilename -DestinationVdcId $destinationvdc
            if (($destinationstorageProfile) -eq $false) 
            { Write-Error ("Invalid Storage Profile Name $destinationstorageProfile"); Break }

            #Build url body 
            [hashtable]$source = @{
                type   = $sourcetype
                site   = $sourcesite
                vappid = $sourcevappId
            }
        
            [hashtable]$destination = @{
                type = $destinationtype
                site = $destinationsite
                vdc  = $destinationvdc
                storageprofile = $destinationstorageProfile
            }
        
            [hashtable]$retentionpolicy = @{
                rules = $retentionpolicyrule
            }
        
            [hashtable]$retentionpolicyrule = @{
                numberOfInstances = $retentionPolicynumberOfInstances
                distance = $retentionPolicydistance
            }
        
            [hashtable]$body = @{
                source = $source
                destination = $destination
                description = $description
                rpo = $rpo
                dataConnectionType = $dataConnectionType
                quiesced = $quiesced
                retentionPolicy = $retentionpolicy
                targetDiskType = $targetDiskType
                initialSyncTime = $initialSyncTime
                isMigration = $isMigration
            }
        
            $json_body = convertto-json -InputObject $body -Depth 4
        
            Write-Verbose ("Message body contains : $body")
            Write-Verbose ("JSON : ' $json_body") 
        
            $UriParams = @{
                QueryPath = 'vapp-replications'
            }
        
            $uri = New-VCAVUrl @UriParams
        
            $Headers = @{ } 
            $Token = Get-VCAVToken
        
            if ($Token -is [array]) { $Token = $Token[0] }
            $Headers.Add('X-VCAV-Auth', $Token)
            $Headers.Add('Accept', 'application/vnd.vmware.h4-v3+json;charset=UTF-8')

        
            $InvokeParams = @{
                Method    = 'POST'
                Body      = $json_body
                Uri       = $uri  
                Headers   = $Headers
                ContentType = 'application/json'
            }
    
            Write-Verbose ("Calling API with parameters : $InvokeParams")
        }

        process {
            Try {
                $result = Invoke-RestMethod @InvokeParams -ErrorAction Stop
                return $result
            }
            Catch {
                Write-Error ("vCloud Availability API error: $($_.Exception.Message)")
                Write-Verbose "$_"
                }
                Break
        }

    }


function Disable-VCAVReplication {
    <#
    .SYNOPSIS
    Stops replication via the vCloud Availability (VCAV) API
    .DESCRIPTION
    Disable-VCAVReplication removes a VM or vApp replication, returning the replication 
    as a PSCustomObject. Currently only supports vCloud Director
    site to site replication and only VM replications (see Examples).
    .PARAMETER vApp
    The name of the replicated vApp
    .OUTPUTS
    A PSCustomObject containing the resources from the API call or an error.
    .EXAMPLE
    Disable an existing replication betwen vCloud Director sites
    Disable-VCAVReplication -SurcevAppName 'MyVapp'
    .NOTES
    Not yet implimented
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$sourcevappname
    )
    
    begin {
        if ($PSCmdlet.SessionState.PSVariable.GetValue('VCAVIsConnected') -ne $true) # Not authenticated to API
        { Write-Error ("Not connected to VCAV API, authenticate first with Connect-VCAV"); Break }
        
        #Confirm vApp is replicated, grab replicaitonID
        $sourcerepid = (Invoke-VCAVQuery -QueryPath 'vapp-replications' -Filter @{vappName='$sourcevappname'}).items.vmReplications.ID

        if (($sourcerepid) -eq $false) 
        { Write-Error ("Invalid vApp Name $sourcevappname"); Break }
   
        $UriParams = @{
            QueryPath = "/vapp-replications/$sourcerepid"
        }
    
        $uri = New-VCAVUrl @UriParams
    
        $Headers = @{ } 
        $Token = Get-VCAVToken
    
        if ($Token -is [array]) { $Token = $Token[0] }
        $Headers.Add('X-VCAV-Auth', $Token)
        $Headers.Add('Accept', 'application/vnd.vmware.h4-v3+json;charset=UTF-8')
 
        $InvokeParams = @{
            Method    = 'DELETE'
            Uri       = $uri  
            Headers   = $Headers
            ContentType = 'application/json'
        }
  
        Write-Verbose ("Calling API with parameters : $InvokeParams")
    }

    process {
        Try {
            $result = Invoke-RestMethod @InvokeParams -ErrorAction Stop
            return $result
        }
        Catch {
            Write-Error ("vCloud Availability API error: $($_.Exception.Message)")
            Write-Verbose "$_"
            }
            Break
                    
    }
    
    end {
    }
}


# Export the public functions from this module to the environment:
Export-ModuleMember -Function Connect-VCAV
Export-ModuleMember -Function Disconnect-VCAV
Export-ModuleMember -Function Connect-VCAVExtend
Export-ModuleMember -Function Invoke-VCAVQuery
Export-ModuleMember -Function Invoke-VCAVPagedQuery
Export-ModuleMember -Function Get-VCAVToken
Export-ModuleMember -Function New-VCAVReplication
Export-ModuleMember -Function Disable-VCAVReplication
