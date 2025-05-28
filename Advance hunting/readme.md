# 🕵️ Advanced Hunting Queries for AD-related Events

## MDI events 
* [Microsoft Defender for Identity monitored activities](https://learn.microsoft.com/en-us/defender-for-identity/monitored-activities)
* [Event collection with Microsoft Defender for Identity](https://learn.microsoft.com/en-us/defender-for-identity/deploy/event-collection-overview)



## 1. ❌ User Logon Failures

```kql
IdentityLogonEvents
//| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-27 23:59:59))  // Filter by time range (UTC) 
| where ActionType == "LogonFailed"                      // Filter only failed logon attempts
| project Timestamp,                                      // Time when the logon attempt occurred
          AccountName,                                    // Username used in the logon attempt
          AccountDomain,                                  // Domain where the logon was attempted
          LogonType,                                      // Type of logon (e.g., interactive, remote)
          FailureReason,                                  // Description of why the logon failed
          ReportId                                        // Unique ID for correlating events
| order by Timestamp desc                                 // Show the most recent events first
```

---

## 2. 🔁 Account Lifecycle Events (Enable / Disable / Delete)

```kql
IdentityDirectoryEvents
//| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-27 23:59:59))  // Filter by time range (UTC) 
| where ActionType in ("Account enabled", "Account disabled", "Account Deleted changed")  // Filter for lifecycle changes
| extend AF = parse_json(AdditionalFields)                // Parse the AdditionalFields JSON for deeper info
| extend ActorAccount = AF["ACTOR.ACCOUNT"]               // Extract the actor (user who performed the action)
| project Timestamp,                                      // Time when the change occurred
          ActionType,                                     // Type of change (enable/disable/delete)
          ActorAccount,                                   // User who triggered the action
          TargetAccountDisplayName,                       // Display name of the account that was changed
          TargetDeviceName                                // Device name if related (e.g., for device accounts)
| order by Timestamp desc                                 // Sort by most recent
```

---

## 3. ✅ Account / Device / Group Creation

```kql
IdentityDirectoryEvents
//| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-27 23:59:59))  // Filter by time range (UTC) 
| where ActionType in ("Security Group Created", "User Account Created", "Device Account Created")  // Track new object creations
| extend AF = parse_json(AdditionalFields)                       // Parse JSON fields to extract deeper context
| extend
    ActorAccount = AF["ACTOR.ACCOUNT"],                          // Who created the object
    TargetUser = AF["TARGET_OBJECT.USER"],                       // Created username (if user account)
    TargetGroup = AF["TARGET_OBJECT.GROUP"],                     // Created group name (if group)
    TargetDevice = AF["TARGET_OBJECT.DEVICE"],                   // Created device name (if computer account)
    TargetEntityUser = AF["TARGET_OBJECT.ENTITY_USER"]           // Sometimes also stores username
| extend
    TargetType = case(                                           // Classify target object type
        isnotempty(TargetUser), "User",                          // If user field exists
        isnotempty(TargetEntityUser) and isempty(TargetGroup) and isempty(TargetDevice), "User",  // Fallback user detection
        isnotempty(TargetGroup), "Group",                        // If group field exists
        isnotempty(TargetDevice), "Device",                      // If device field exists
        "Unknown"                                                // If none matched
    ),
    TargetName = coalesce(TargetUser, TargetGroup, TargetDevice, TargetEntityUser)  // Pick the available name field
| project Timestamp,                                             // Event time
          ActionType,                                            // Type of creation
          ActorAccount,                                          // Who performed the creation
          TargetType,                                            // What kind of object was created
          TargetName                                             // Name of the created object
| order by Timestamp desc                                        // Recent events first
```

---

## 4. 🗑️ Account / Device / Group Deletion

```kql
IdentityDirectoryEvents
//| where Timestamp between (datetime(2025-05-25 00:00:00) .. datetime(2025-05-27 23:59:59))  // Filter by time range (UTC) 
| where ActionType contains "Account Deleted changed"           // Filter for deletion-related actions
| extend AF = parse_json(AdditionalFields)                      // Parse the AdditionalFields JSON blob
| extend
    ActorAccount = AF["ACTOR.ACCOUNT"],                         // Who deleted the object
    TargetUser = AF["TARGET_OBJECT.USER"],                      // Deleted user account name (if applicable)
    TargetGroup = AF["TARGET_OBJECT.GROUP"],                    // Deleted group name (if applicable)
    TargetDevice = AF["TARGET_OBJECT.DEVICE"],                  // Deleted device name (if applicable)
    TargetEntityUser = AF["TARGET_OBJECT.ENTITY_USER"]          // Sometimes used for user names
| extend
    TargetType = case(                                          // Determine object type
        isnotempty(TargetUser), "User",                         // If user field exists
        isnotempty(TargetGroup), "Group",                       // If group field exists
        isnotempty(TargetDevice), "Device",                     // If device field exists
        isnotempty(TargetEntityUser) and isempty(TargetUser) and isempty(TargetDevice), "Group", // Fallback for group
        "Unknown"                                               // No matching field found
    ),
    TargetName = coalesce(TargetUser, TargetGroup, TargetDevice, TargetEntityUser)  // Resolve target name
| project Timestamp,                                            // Deletion time
          ActionType,                                           // Type of delete event
          ActorAccount,                                         // Who performed the deletion
          TargetType,                                           // Type of deleted object
          TargetName                                            // Name of deleted object
| order by Timestamp desc                                       // Sort by latest events
```
