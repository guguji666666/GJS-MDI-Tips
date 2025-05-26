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


