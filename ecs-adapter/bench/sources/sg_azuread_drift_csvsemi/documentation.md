# Azure AD sign-in log

Positional columns separated by ";", one entry per line.

```
TIME_;CALLERIPADDRESS;PROPERTIES_RESOURCEDISPLAYNAME;DURATIONMS;PROPERTIES_RESOURCEID;PROPERTIES_PROCESSINGTIMEINMILLISECONDS;PROPERTIES_LOCATION_GEOCOORDINATES_LATITUDE;TIME;PROPERTIES_APPDISPLAYNAME;PROPERTIES_CREATEDDATETIME;PROPERTIES_RISKDETAIL;PROPERTIES_LOCATION_COUNTRYORREGION;OPERATIONVERSION;CATEGORY;PROPERTIES_USERTYPE;PROPERTIES_RISKLEVELDURINGSIGNIN;PROPERTIES_DEVICEDETAIL_DEVICEID;PROPERTIES_USERPRINCIPALNAME;PROPERTIES_APPID;LOCATION;PROPERTIES_INCOMINGTOKENTYPE;TENANTID;LEVEL;IDENTITY;CORRELATIONID;RESULTDESCRIPTION;PROPERTIES_LOCATION_STATE;PROPERTIES_AUTHENTICATIONPROTOCOL;PROPERTIES_LOCATION_GEOCOORDINATES_LONGITUDE;PROPERTIES_USERID;PROPERTIES_CROSSTENANTACCESSTYPE;PROPERTIES_STATUS_FAILUREREASON;RESULTTYPE;PROPERTIES_RISKSTATE;PROPERTIES_CONDITIONALACCESSSTATUS;PROPERTIES_CORRELATIONID;PROPERTIES_UNIQUETOKENIDENTIFIER;PROPERTIES_RISKLEVELAGGREGATED;PROPERTIES_LOCATION_CITY;RESULTSIGNATURE;PROPERTIES_IPADDRESS;PROPERTIES_STATUS_ERRORCODE;PROPERTIES_DEVICEDETAIL_TRUSTTYPE;PROPERTIES_DEVICEDETAIL_BROWSER;PROPERTIES_ID;PROPERTIES_DEVICEDETAIL_OPERATINGSYSTEM;OPERATIONNAME;PROPERTIES_USERDISPLAYNAME;PROPERTIES_TOKENISSUERTYPE;PROPERTIES_STATUS_ADDITIONALDETAILS;PROPERTIES_AUTHENTICATIONREQUIREMENT;RESOURCEID;PROPERTIES_DEVICEDETAIL_DISPLAYNAME;PROPERTIES_CLIENTAPPUSED
```

Example lines:

```
2026-10-14T08:00:19+00:00;194.65.159.130;Device Registration Service;0;1e0c3da6-f0fc-e345-e7c0-298c9db84641;205;38.72;2026-10-14T08:00:19.0000000Z;Microsoft Authentication Broker;2026-10-14T08:00:19.0000000Z;none;PT;1.0;SignInLogs;Member;none;c65f6b23-a894-0209-4b1e-bb5d1d5a0f8f;kyle.cabrera@acme.local;29d9ed98-a469-4536-ade2-f981bc1d605e;PT;none;da257cd4-2a96-3ef3-2e37-1bfe18f4bebd;4;Kyle Cabrera;0f54f304-45a3-577e-18a0-a5abcca95bf8;Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.;Lisboa;none;-9.14;5e8ac8de-5af8-0305-cb65-9607ecbbbc17;none;Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.;53003;none;failure;d00d68df-6db7-5d0c-3f7e-b9340051e467;b4a36ee0987b3544242b30e58d656ec4;none;Lisbon;None;194.65.159.130;53003;Azure AD joined;Firefox 125.0;e2f8559f-823c-def7-f73e-dd77b6c29163;Windows10;Sign-in activity;Kyle Cabrera;AzureAD;;multiFactorAuthentication;/tenants/da257cd4-2a96-3ef3-2e37-1bfe18f4bebd/providers/Microsoft.aadiam;WS-EXE-001;Browser
2026-10-14T08:00:34+00:00;194.65.159.130;Office 365 SharePoint Online;0;a0ceee73-c6d7-d052-e643-596c41122d9b;182;38.72;2026-10-14T08:00:34.0000000Z;OneDrive SyncEngine;2026-10-14T08:00:34.0000000Z;none;PT;1.0;NonInteractiveUserSignInLogs;Member;none;761d3d4a-ea93-9392-6368-476ff616ddb2;danielle.watson@acme.local;ab9b8c07-8f02-4f72-87fa-80105867a763;PT;none;da257cd4-2a96-3ef3-2e37-1bfe18f4bebd;4;Danielle Watson;19cd5840-f1ae-c544-ad77-bf39768915e2;;Lisboa;none;-9.14;df572430-1471-9c5a-f9f8-7f7be3e4520b;none;Other.;0;none;success;d9078d3f-e0a0-887b-ee1a-fbfa45289e00;2c358452358902ff3177e7e8c92637e6;none;Lisbon;None;194.65.159.130;0;Azure AD joined;;ed4a2243-7740-af0d-c481-ee214e69886d;Windows10;Sign-in activity;Danielle Watson;AzureAD;;singleFactorAuthentication;/tenants/da257cd4-2a96-3ef3-2e37-1bfe18f4bebd/providers/Microsoft.aadiam;WS-GENERAL-002;Exchange ActiveSync
```

- `time_` — timestamp as written
- `callerIpAddress` — remote peer IP
- `properties_resourceDisplayName` — recorded by the source
- `durationMs` — vendor-specific value
- `properties_resourceId` — internal to the product
- `properties_processingTimeInMilliseconds` — internal to the product
- `properties_location_geoCoordinates_latitude` — kept as written
- `time` — kept as written
- `properties_appDisplayName` — recorded by the source
- `properties_createdDateTime` — kept as written
- `properties_riskDetail` — kept as written
- `properties_location_countryOrRegion` — recorded by the source
- `operationVersion` — recorded by the source
- `category` — internal to the product
- `properties_userType` — kept as written
- `properties_riskLevelDuringSignIn` — vendor-specific value
- `properties_deviceDetail_deviceId` — recorded by the source
- `properties_userPrincipalName` — e-mail
- `properties_appId` — recorded by the source
- `location` — vendor-specific value
- `properties_incomingTokenType` — internal to the product
- `tenantId` — kept as written
- `Level` — recorded by the source
- `identity` — person's name as shown in the directory
- `correlationId` — kept as written
- `resultDescription` — recorded by the source
- `properties_location_state` — internal to the product
- `properties_authenticationProtocol` — internal to the product
- `properties_location_geoCoordinates_longitude` — internal to the product
- `properties_userId` — uid
- `properties_crossTenantAccessType` — internal to the product
- `properties_status_failureReason` — internal to the product
- `resultType` — internal to the product
- `properties_riskState` — vendor-specific value
- `properties_conditionalAccessStatus` — verdict
- `properties_correlationId` — recorded by the source
- `properties_uniqueTokenIdentifier` — vendor-specific value
- `properties_riskLevelAggregated` — recorded by the source
- `properties_location_city` — vendor-specific value
- `resultSignature` — vendor-specific value
- `properties_ipAddress` — internal to the product
- `properties_status_errorCode` — internal to the product
- `properties_deviceDetail_trustType` — recorded by the source
- `properties_deviceDetail_browser` — kept as written
- `properties_id` — queue ID
- `properties_deviceDetail_operatingSystem` — recorded by the source
- `operationName` — operation
- `properties_userDisplayName` — kept as written
- `properties_tokenIssuerType` — internal to the product
- `properties_status_additionalDetails` — recorded by the source
- `properties_authenticationRequirement` — recorded by the source
- `resourceId` — internal to the product
- `properties_deviceDetail_displayName` — recorded by the source
- `properties_clientAppUsed` — kept as written
