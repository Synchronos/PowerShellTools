#Requires -Modules ActiveDirectory
function Get-ComparisonResult ($name1, $name2, $sideIndicator)
{
    $comparisonResult = $null

    switch ($_.SideIndicator)
    {
        '<=' { $comparisonResult = "$($name1) Only" }
        '==' { $comparisonResult = "$($name1) and $($name2)" }
        '=>' { $comparisonResult = "$($name2) Only" }
    }

    return $comparisonResult
}


function Compare-ADUserGroupMembership
{
    <#
    .SYNOPSIS
        Compares the group memberships of two Active Directory users.
    .DESCRIPTION
        Compares the group memberships of two Active Directory users and reports each group and which users are members of them.
    .PARAMETER IncludeNestedGroups
        If this switch is present, memberships as a result of group nesting will be included in the output.
    .PARAMETER UserName1
        The name of an Active Directory user.
    .PARAMETER UserName2
        The name of an Active Directory user.
    .EXAMPLE
        Compare-ADUserGroupMembership 'userone225' 'usertwo225' | ft -AutoSize
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter()]
        [switch] $IncludeNestedGroups,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $UserName1,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $UserName2
    )

    begin
    {
        $userComparisonResultColumn = @{ name = 'Comparison Result'; expression = { Get-ComparisonResult $user1.DisplayName $user2.DisplayName  $_.SideIndicator } }
        $groupNameColumn = @{ name = 'Group Name'; expression = { $_.Name } }
        $membershipTypeColumn = @{ name = 'Membership Type'; expression = { $_.MembershipType } } 
    }

    process
    {
        try
        {
            $user1 = Get-ADUser $UserName1 -Properties memberOf, displayName
            $user2 = Get-ADUser $UserName2 -Properties memberOf, displayName

            if ($IncludeNestedGroups -eq $false)
            {
                $groups1 = Get-ADPrincipalGroupMembership $UserName1 | Select *, @{ Name = 'MembershipType'; expression = { 'Direct' } }
                $groups2 = Get-ADPrincipalGroupMembership $UserName2 | Select *, @{ Name = 'MembershipType'; expression = { 'Direct' } }
            }
            else
            {
                $groups1 = Get-ADGroup -LdapFilter "(member:1.2.840.113556.1.4.1941:=$($user1.DistinguishedName))" | Select *, @{ Name = 'MembershipType'; expression = { if ($user1.memberof -contains $_.DistinguishedName) { 'Direct' } else { 'Nested' } } }
                $groups2 = Get-ADGroup -LdapFilter "(member:1.2.840.113556.1.4.1941:=$($user2.DistinguishedName))" | Select *, @{ Name = 'MembershipType'; expression = { if ($user2.memberof -contains $_.DistinguishedName) { 'Direct' } else { 'Nested' } } }
            }
        }
        catch
        {
            if ($null -eq $user1)
            {
                Write-Warning "Cannot compare because $($UserName1) could not be retrieved."
            }

            if ($null -eq $user2)
            {
                Write-Warning "Cannot compare because $($UserName2) could not be retrieved."
            }
        }

        if ($null -ne $user1 -and $null -ne $user2)
        {
            $userGroupComparison = Compare-Object -IncludeEqual $groups1 $groups2 -Property Name, MembershipType, DistinguishedName | Sort SideIndicator, MembershipType, Name | Select $groupNameColumn, $membershipTypeColumn, $userComparisonResultColumn
        }

        return $userGroupComparison
    }
}

function Compare-ADGroupMembership
{
    <#
    .SYNOPSIS
        Compares the group memberships of two Active Directory groups.
    .DESCRIPTION
        Compares the group memberships of two Active Directory Groups and reports each user and which group or groups they are members of.
    .PARAMETER GroupName1
        The name of an Active Directory group.
    .PARAMETER GroupName2
        The name of an Active Directory group.
    .EXAMPLE
        Compare-ADGroupMembership 'Group One' 'Group Two' | ft -AutoSize
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string] $GroupName1,
        [Parameter(Mandatory = $true, ValueFromPipeline = $false, ValueFromPipelineByPropertyName = $true, Position = 1)]
        [string] $GroupName2
    )

    begin
    {
        $groupComparisonResultColumn = @{ name = 'Comparison Result'; expression = { Get-ComparisonResult $groupName1 $groupName2 $_.SideIndicator } }
        $userNameColumn = @{ name = 'User Name'; expression = { $_.InputObject.name } }
    }

    process
    {
        try
        {
            $groupMembers1 = Get-ADGroupMember $GroupName1
        }
        catch
        {
            if ($null -eq $groupMembers1)
            {
                Write-Warning "Cannot compare because $($GroupName1) could not be retrieved. $($Error[0])"
            }
        }

        try
        {
            $groupMembers2 = Get-ADGroupMember $GroupName2
        }
        catch
        {
            if ($null -eq $groupMembers2)
            {
                Write-Warning "Cannot compare because $($GroupName2) could not be retrieved. $($Error[0])"
            }
        }

        if ($null -ne $groupMembers1 -and $null -ne $groupMembers2)
        {
            $groupMemberComparison = Compare-Object -IncludeEqual $groupMembers1 $groupMembers2 | Select $userNameColumn, $groupComparisonResultColumn
        }

        return  $groupMemberComparison
    }
}
