# Azure AD sign-in log

Key=value pairs separated by "; ", key and value joined by "=", one entry per line.

```
time_=TIME_; time=TIME; properties_location_state=PROPERTIES_LOCATION_STATE; properties_incomingTokenType=PROPERTIES_INCOMINGTOKENTYPE; durationMs=DURATIONMS; operationVersion=OPERATIONVERSION; properties_userType=PROPERTIES_USERTYPE; resourceId=RESOURCEID; properties_correlationId=PROPERTIES_CORRELATIONID; properties_authenticationRequirement=PROPERTIES_AUTHENTICATIONREQUIREMENT; properties_location_city=PROPERTIES_LOCATION_CITY; properties_userDisplayName=PROPERTIES_USERDISPLAYNAME; properties_location_geoCoordinates_longitude=PROPERTIES_LOCATION_GEOCOORDINATES_LONGITUDE; properties_location_countryOrRegion=PROPERTIES_LOCATION_COUNTRYORREGION ...
```

Example lines:

```
time_=2026-10-14T08:00:19+00:00; time=2026-10-14T08:00:19.0000000Z; properties_location_state=Lisboa; properties_incomingTokenType=none; durationMs=0; operationVersion=1.0; properties_userType=Member; resourceId=/tenants/da257cd4-2a96-3ef3-2e37-1bfe18f4bebd/providers/Microsoft.aadiam; properties_correlationId=d00d68df-6db7-5d0c-3f7e-b9340051e467; properties_authenticationRequirement=multiFactorAuthentication; properties_location_city=Lisbon; properties_userDisplayName="Kyle Cabrera"; properties_location_geoCoordinates_longitude=-9.14; properties_location_countryOrRegion=PT; properties_deviceDetail_deviceId=c65f6b23-a894-0209-4b1e-bb5d1d5a0f8f; properties_appDisplayName="Microsoft Authentication Broker"; properties_status_errorCode=53003; Level=4; properties_status_failureReason="Access has been blocked by Conditional Access policies. The access policy does not allow token issuance."; location=PT; properties_userId=5e8ac8de-5af8-0305-cb65-9607ecbbbc17; properties_crossTenantAccessType=none; properties_ipAddress=194.65.159.130; category=SignInLogs; identity="Kyle Cabrera"; properties_riskState=none; properties_deviceDetail_displayName=WS-EXE-001; properties_riskLevelDuringSignIn=none; properties_createdDateTime=2026-10-14T08:00:19.0000000Z; resultSignature=None; properties_riskLevelAggregated=none; properties_clientAppUsed=Browser; properties_deviceDetail_operatingSystem=Windows10; properties_deviceDetail_trustType="Azure AD joined"; callerIpAddress=194.65.159.130; tenantId=da257cd4-2a96-3ef3-2e37-1bfe18f4bebd; properties_processingTimeInMilliseconds=205; resultDescription="Access has been blocked by Conditional Access policies. The access policy does not allow token issuance."; properties_resourceId=1e0c3da6-f0fc-e345-e7c0-298c9db84641; correlationId=0f54f304-45a3-577e-18a0-a5abcca95bf8; properties_resourceDisplayName="Device Registration Service"; properties_authenticationProtocol=none; properties_location_geoCoordinates_latitude=38.72; properties_uniqueTokenIdentifier=b4a36ee0987b3544242b30e58d656ec4; properties_riskDetail=none; properties_appId=29d9ed98-a469-4536-ade2-f981bc1d605e; properties_conditionalAccessStatus=failure; resultType=53003; properties_tokenIssuerType=AzureAD; properties_userPrincipalName=kyle.cabrera@acme.local; properties_id=e2f8559f-823c-def7-f73e-dd77b6c29163; operationName="Sign-in activity"; properties_deviceDetail_browser="Firefox 125.0"
time_=2026-10-14T08:00:34+00:00; time=2026-10-14T08:00:34.0000000Z; properties_location_state=Lisboa; properties_incomingTokenType=none; durationMs=0; operationVersion=1.0; properties_userType=Member; resourceId=/tenants/da257cd4-2a96-3ef3-2e37-1bfe18f4bebd/providers/Microsoft.aadiam; properties_correlationId=d9078d3f-e0a0-887b-ee1a-fbfa45289e00; properties_authenticationRequirement=singleFactorAuthentication; properties_location_city=Lisbon; properties_userDisplayName="Danielle Watson"; properties_location_geoCoordinates_longitude=-9.14; properties_location_countryOrRegion=PT; properties_deviceDetail_deviceId=761d3d4a-ea93-9392-6368-476ff616ddb2; properties_appDisplayName="OneDrive SyncEngine"; properties_status_errorCode=0; Level=4; properties_status_failureReason=Other.; location=PT; properties_userId=df572430-1471-9c5a-f9f8-7f7be3e4520b; properties_crossTenantAccessType=none; properties_ipAddress=194.65.159.130; category=NonInteractiveUserSignInLogs; identity="Danielle Watson"; properties_riskState=none; properties_deviceDetail_displayName=WS-GENERAL-002; properties_riskLevelDuringSignIn=none; properties_createdDateTime=2026-10-14T08:00:34.0000000Z; resultSignature=None; properties_riskLevelAggregated=none; properties_clientAppUsed="Exchange ActiveSync"; properties_deviceDetail_operatingSystem=Windows10; properties_deviceDetail_trustType="Azure AD joined"; callerIpAddress=194.65.159.130; tenantId=da257cd4-2a96-3ef3-2e37-1bfe18f4bebd; properties_processingTimeInMilliseconds=182; properties_resourceId=a0ceee73-c6d7-d052-e643-596c41122d9b; correlationId=19cd5840-f1ae-c544-ad77-bf39768915e2; properties_resourceDisplayName="Office 365 SharePoint Online"; properties_authenticationProtocol=none; properties_location_geoCoordinates_latitude=38.72; properties_uniqueTokenIdentifier=2c358452358902ff3177e7e8c92637e6; properties_riskDetail=none; properties_appId=ab9b8c07-8f02-4f72-87fa-80105867a763; properties_conditionalAccessStatus=success; resultType=0; properties_tokenIssuerType=AzureAD; properties_userPrincipalName=danielle.watson@acme.local; properties_id=ed4a2243-7740-af0d-c481-ee214e69886d; operationName="Sign-in activity"
```

- `time_` — when the entry was logged
- `time` — vendor-specific value
- `properties_location_state` — kept as written
- `properties_incomingTokenType` — internal to the product
- `durationMs` — kept as written
- `operationVersion` — vendor-specific value
- `properties_userType` — internal to the product
- `resourceId` — internal to the product
- `properties_correlationId` — vendor-specific value
- `properties_authenticationRequirement` — internal to the product
- `properties_location_city` — internal to the product
- `properties_userDisplayName` — kept as written
- `properties_location_geoCoordinates_longitude` — vendor-specific value
- `properties_location_countryOrRegion` — internal to the product
- `properties_deviceDetail_deviceId` — vendor-specific value
- `properties_appDisplayName` — vendor-specific value
- `properties_status_errorCode` — vendor-specific value
- `Level` — kept as written
- `properties_status_failureReason` — internal to the product
- `location` — recorded by the source
- `properties_userId` — uid
- `properties_crossTenantAccessType` — kept as written
- `properties_ipAddress` — kept as written
- `category` — internal to the product
- `identity` — full name
- `properties_riskState` — recorded by the source
- `properties_deviceDetail_displayName` — recorded by the source
- `properties_riskLevelDuringSignIn` — recorded by the source
- `properties_createdDateTime` — kept as written
- `resultSignature` — kept as written
- `properties_riskLevelAggregated` — internal to the product
- `properties_clientAppUsed` — vendor-specific value
- `properties_deviceDetail_operatingSystem` — internal to the product
- `properties_deviceDetail_trustType` — recorded by the source
- `callerIpAddress` — IP of the requesting host
- `tenantId` — vendor-specific value
- `properties_processingTimeInMilliseconds` — vendor-specific value
- `resultDescription` — recorded by the source
- `properties_resourceId` — recorded by the source
- `correlationId` — vendor-specific value
- `properties_resourceDisplayName` — vendor-specific value
- `properties_authenticationProtocol` — vendor-specific value
- `properties_location_geoCoordinates_latitude` — recorded by the source
- `properties_uniqueTokenIdentifier` — recorded by the source
- `properties_riskDetail` — internal to the product
- `properties_appId` — internal to the product
- `properties_conditionalAccessStatus` — result word
- `resultType` — kept as written
- `properties_tokenIssuerType` — vendor-specific value
- `properties_userPrincipalName` — UPN or mailbox
- `properties_id` — queue ID
- `operationName` — action
- `properties_deviceDetail_browser` — recorded by the source
- `properties_status_additionalDetails` — vendor-specific value
