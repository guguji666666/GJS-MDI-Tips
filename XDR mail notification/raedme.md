# XDR mail notification 

## Test with MDI alert as trigger

### 1. Navigate to XDR portal (security.microsoft.com)
### 2. Navigate to System > settings > Microsoft Defender XDR > Email notifications > Incidents > Add incident notification rule
![image](https://github.com/user-attachments/assets/d4745bf8-1984-4446-a078-8c06ad626bac)

### 3. Create the rule

Fill in rule name and description
![image](https://github.com/user-attachments/assets/333e3050-1f39-443c-9166-858d62c4b8c2)

Fill in alert severity, and source that fires notification
![image](https://github.com/user-attachments/assets/314b78f2-f081-44c9-b9f2-4cb1bfdb93b0)


Fill in recipients
![image](https://github.com/user-attachments/assets/ec728a7f-577c-4cb0-a407-3ce899422f44)


Review the configuraion and confirm creation
![image](https://github.com/user-attachments/assets/4d559f6a-f445-472b-8f0c-b5a5307d1e49)


### 4. Manually generate alert (in this sample we test honey token alert as metnioend in https://learn.microsoft.com/en-us/defender-for-identity/credential-access-alerts#honeytoken-authentication-activity-external-id-2014)

Description:

Honeytoken accounts are decoy accounts set up to identify and track malicious activity that involves these accounts. Honeytoken accounts should be left unused while having an attractive name to lure attackers (for example, SQL-Admin). Any authentication activity from them might indicate malicious behavior. For more information on honeytoken accounts, see Manage sensitive or honeytoken accounts.


### 5. Review notification sent to mailboxes
