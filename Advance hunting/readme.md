# Advance hunting for AD events
## 1. User Logon Failures
```kql
IdentityLogonEvents
| where ActionType == "LogonFailed"
| project Timestamp, AccountName, AccountDomain, LogonType, FailureReason, ReportId
| order by Timestamp desc
```


## 2. Account Lifecycle Events (Enable/Disable/Delete)
```kql
IdentityDirectoryEvents
| where ActionType in ("Account enabled", "Account disabled", "Account Deleted changed")
| extend AF = parse_json(AdditionalFields)
| extend ActorAccount = AF["ACTOR.ACCOUNT"]
| project Timestamp, ActionType, ActorAccount, TargetAccountDisplayName, TargetDeviceName
| order by Timestamp desc
```

## 3. User account, security group created
```kql
IdentityDirectoryEvents
| where ActionType in ("Security Group Created", "User Account Created")
// | extend AF = parse_json(AdditionalFields)
// | extend ActorAccount = AF["ACTOR.ACCOUNT"]
// | project Timestamp, ActionType, ActorAccount, TargetAccountDisplayName, TargetDeviceName
| order by Timestamp desc
```

## 4. User/device/group object deleted
```kql
IdentityDirectoryEvents
| where ActionType contains "Account Deleted changed"
| extend AF = parse_json(AdditionalFields)
| extend 
    ActorAccount = AF["ACTOR.ACCOUNT"],
    TargetUser = AF["TARGET_OBJECT.USER"],
    TargetGroup = AF["TARGET_OBJECT.GROUP"],
    TargetEntityUser = AF["TARGET_OBJECT.ENTITY_USER"]
| extend 
    TargetType = case(
        isnotempty(TargetUser), "User",
        isnotempty(TargetGroup), "Group",
        isnotempty(TargetEntityUser) and isempty(TargetUser), "Group",  // fallback heuristic
        "Unknown"
    ),
    TargetName = coalesce(TargetUser, TargetGroup, TargetEntityUser)
| project Timestamp, ActionType, ActorAccount, TargetType, TargetName
| order by Timestamp desc
```
